#!/usr/bin/env python3
# BIP133 feefilter over the wire (run under `unshare -rn`; brings lo up itself).
# `indexerd serve doge` with two inbound fake peers: A sends feefilter after
# verack, B feeds txs. Checks the three serve-loop paths: inv on tx accept,
# the BIP35 mempool reply, and getdata (held-back tx -> notfound). A tx whose
# fee rate is UNKNOWN (spends a confirmed outpoint; no UTXO set) must still be
# relayed under any filter — only txs KNOWN to be below it are held back.
import hashlib, os, socket, sqlite3, struct, subprocess, sys, tempfile, time
IDX = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'indexerd')
MAGIC = bytes([0xC0, 0xC0, 0xC0, 0xC0])
subprocess.call(['ip', 'link', 'set', 'lo', 'up'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
fails = 0
def ck(c, n):
    global fails
    print(('ok   ' if c else 'FAIL ') + n); fails += 0 if c else 1
def d2(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def msg(cmd, p=b''):
    return MAGIC + cmd.encode().ljust(12, b'\0') + struct.pack('<I', len(p)) + d2(p)[:4] + p
def version(h):
    return (struct.pack('<iQq', 70015, 1, int(time.time())) + bytes(52) +
            os.urandom(8) + b'\x08/t:0.1/' + struct.pack('<i', h) + b'\x01')
def recv_cmd(c):
    h = b''
    while len(h) < 24:
        x = c.recv(24 - len(h))
        if not x: raise EOFError
        h += x
    n = struct.unpack('<I', h[16:20])[0]; p = b''
    while len(p) < n:
        x = c.recv(n - len(p))
        if not x: raise EOFError
        p += x
    return h[4:16].rstrip(b'\0').decode(), p
def p2pkh(v, tag): return struct.pack('<q', v) + b'\x19\x76\xa9\x14' + bytes([tag]) * 20 + b'\x88\xac'
def tx(prev, vout, outs):
    b = struct.pack('<i', 1) + b'\x01' + prev + struct.pack('<I', vout) + b'\x01\x51' + b'\xff' * 4
    b += bytes([len(outs)]) + b''.join(outs) + bytes(4)
    return b, d2(b)
def inv1(t, h): return b'\x01' + struct.pack('<I', t) + h

class Peer:
    def __init__(self, port, ff_before=None):
        self.s = socket.create_connection(('127.0.0.1', port), timeout=5)
        self.s.sendall(msg('version', version(0)))
        if ff_before is not None: self.s.sendall(msg('feefilter', struct.pack('<q', ff_before)))
        got = set()
        while not {'version', 'verack'} <= got:
            got.add(recv_cmd(self.s)[0])
        self.s.sendall(msg('verack'))
        self.sync()
    def send(self, cmd, p=b''): self.s.sendall(msg(cmd, p))
    def sync(self):
        """ping/pong barrier: everything sent before is processed; returns msgs seen meanwhile."""
        n = os.urandom(8); self.send('ping', n); seen = []
        while True:
            cmd, p = recv_cmd(self.s)
            if cmd == 'pong' and p == n: return seen
            seen.append((cmd, p))
    def invs(self):
        out = set()
        for cmd, p in self.sync():
            if cmd == 'inv':
                for i in range(p[0]): out.add(p[1 + 36 * i + 4:1 + 36 * i + 36])
        return out

d = tempfile.mkdtemp(); db = os.path.join(d, 'db1')
s = sqlite3.connect(os.path.join(d, 'serve-doge.db'))
s.executescript("CREATE TABLE headers(height INTEGER PRIMARY KEY, hash BLOB, hdr BLOB);"
                "CREATE INDEX headers_hash ON headers(hash);"); s.commit(); s.close()
port = 22000 + os.getpid() % 2000
lst = socket.socket(); lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
lst.bind(('127.0.0.2', 0)); lst.listen(4); lst.settimeout(30)
p = subprocess.Popen([IDX, 'serve', 'doge', db, str(port), '127.0.0.2:%d' % lst.getsockname()[1]],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    for _ in range(50):
        try: socket.create_connection(('127.0.0.1', port), timeout=1).close(); break
        except OSError: time.sleep(0.1)
    A = Peer(port); B = Peer(port)
    A.send('feefilter', struct.pack('<q', 1000)); A.sync()
    # 1. 0xD9 carrier spending a CONFIRMED outpoint: rate unknown -> still inv'd
    car, cid = tx(b'\x77' * 32, 0, [struct.pack('<q', 0) + b'\x16\x6a\x14\xd9' + b'\x01' * 19,
                                     p2pkh(500000000, 0x11)])
    B.send('tx', car); B.sync()
    ck(cid in A.invs(), "0xD9 carrier with confirmed parent inv'd to a feefilter=1000 peer")
    # 2. low-fee child (1 koinu over ~190 B, rate known ~5/kB) under filter=50M
    A.send('feefilter', struct.pack('<q', 50000000)); A.sync()
    low, lid = tx(cid, 1, [p2pkh(500000000 - 1, 0x22)])
    B.send('tx', low); B.sync()
    ck(lid not in A.invs(), 'known-low child NOT inv\'d on tx accept to a 50M/kB peer')
    B.invs()
    A.send('mempool'); m = A.invs()
    ck(cid in m and lid not in m, 'mempool reply: unknown-rate carrier listed, known-low child filtered')
    A.send('getdata', inv1(1, lid)); r = A.sync()
    ck(any(c == 'notfound' and pl == inv1(1, lid) for c, pl in r), 'getdata of held-back tx -> notfound')
    ck(not any(c == 'tx' for c, pl in r), 'held-back tx body not served')
    A.send('getdata', inv1(1, cid)); r = A.sync()
    ck(any(c == 'tx' and pl == car for c, pl in r), 'getdata of unknown-rate carrier -> tx served')
    # 3. feefilter sent BEFORE verack is ignored
    C = Peer(port, ff_before=50000000)
    C.send('mempool'); m = C.invs()
    ck(lid in m, 'feefilter before verack ignored (known-low child still listed)')
    # 4. orphan child first, parent second: child becomes known-low and is filtered
    par, pid = tx(b'\x88' * 32, 0, [p2pkh(300000000, 0x33)])
    och, oid = tx(pid, 0, [p2pkh(300000000 - 1, 0x44)])
    B.send('tx', och); B.sync()
    ck(oid in A.invs(), 'orphan child (parent absent, rate unknown) inv\'d')
    B.send('tx', par); B.sync(); A.invs()
    A.send('mempool'); m = A.invs()
    ck(pid in m and oid not in m, 'orphan child recomputed to known-low once its parent arrives')
    # 5. OUTBOUND session (we dialed a configured peer): a feefilter sent before
    # its verack is ignored; one after verack is honoured (got_verack is set from
    # the verack that actually arrived in serve_dial's handshake)
    o, _ = lst.accept(); o.settimeout(5)
    while recv_cmd(o)[0] != 'version': pass
    o.sendall(msg('version', version(0)) + msg('feefilter', struct.pack('<q', 50000000)) + msg('verack'))
    class _O(Peer):
        def __init__(self, s): self.s = s
    F = _O(o); F.sync()
    F.send('mempool'); m = F.invs()
    ck(lid in m, 'outbound: feefilter before verack ignored (known-low child listed)')
    F.send('feefilter', struct.pack('<q', 50000000)); F.sync()
    F.send('mempool'); m = F.invs()
    ck(cid in m and lid not in m, 'outbound: feefilter after verack honoured (known-low child filtered)')
finally:
    p.terminate(); p.wait(5)
sys.exit(1 if fails else 0)
