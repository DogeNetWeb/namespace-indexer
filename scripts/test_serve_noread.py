#!/usr/bin/env python3
# A serve peer that asks for data and then never reads must not wedge the serve
# thread (run under `unshare -rn`; brings lo up itself; hard 90 s kill timer).
# Build: indexerd-stalltest (SERVE_SEND_STALL_S=4). Two attackers with tiny
# receive buffers: A1 spams getdata for big blocks, A2 spams getheaders; neither
# ever reads. Meanwhile an honest peer must still handshake, ping, and pull a
# getdata reply far larger than the per-conn send queue (pacing, not dropping),
# and both attackers must be disconnected.
import hashlib, os, signal, socket, sqlite3, struct, subprocess, sys, tempfile, time
IDX = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'indexerd-stalltest')
MAGIC = bytes([0xC0, 0xC0, 0xC0, 0xC0])
subprocess.call(['ip', 'link', 'set', 'lo', 'up'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
signal.signal(signal.SIGALRM, lambda *a: (print('FAIL hard timeout (90 s)'), os._exit(2)))
signal.alarm(90)
fails = 0
def ck(c, n):
    global fails
    print(('ok   ' if c else 'FAIL ') + n, flush=True); fails += 0 if c else 1
def d2(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def msg(cmd, p=b''):
    return MAGIC + cmd.encode().ljust(12, b'\0') + struct.pack('<I', len(p)) + d2(p)[:4] + p
def version(h):
    return (struct.pack('<iQq', 70015, 1, int(time.time())) + bytes(52) +
            os.urandom(8) + b'\x08/t:0.1/' + struct.pack('<i', h) + b'\x01')
def recv_n(c, n):
    b = b''
    while len(b) < n:
        x = c.recv(n - len(b))
        if not x: raise EOFError
        b += x
    return b
def recv_cmd(c):
    h = recv_n(c, 24); n = struct.unpack('<I', h[16:20])[0]
    return h[4:16].rstrip(b'\0').decode(), recv_n(c, n)
def varint(n): return bytes([n]) if n < 0xFD else b'\xfd' + struct.pack('<H', n)

NBLK, BLKSZ, NHDR = 40, 300 * 1024, 2000
d = tempfile.mkdtemp(); db = os.path.join(d, 'db1')
s = sqlite3.connect(os.path.join(d, 'serve-doge.db'))
s.executescript("CREATE TABLE headers(height INTEGER PRIMARY KEY, hash BLOB, hdr BLOB);"
                "CREATE INDEX headers_hash ON headers(hash);"
                "CREATE TABLE blockwin(height INTEGER PRIMARY KEY, raw BLOB);")
hashes, raws = [], {}
for h in range(NHDR):
    hdr = struct.pack('<I', h) + os.urandom(76); bh = d2(hdr); hashes.append(bh)
    s.execute("INSERT INTO headers VALUES(?,?,?)", (h, bh, hdr))
    if h >= NHDR - NBLK:
        raw = hdr + os.urandom(BLKSZ - 80); raws[bh] = raw
        s.execute("INSERT INTO blockwin VALUES(?,?)", (h, raw))
s.commit(); s.close()
blk_hashes = hashes[-NBLK:]
GETDATA = msg('getdata', varint(NBLK) + b''.join(struct.pack('<I', 2) + bh for bh in blk_hashes))
GETHDRS = msg('getheaders', struct.pack('<I', 70015) + b'\x01' + os.urandom(32) + bytes(32))

def free_port():
    while True:
        t = socket.socket(); t.bind(('127.0.0.1', 0)); pt = t.getsockname()[1]; t.close()
        if pt not in (15353, 8443, 8444, 8445): return pt
port = free_port()
log = open(os.path.join(d, 'serve.log'), 'w')
p = subprocess.Popen([IDX, 'serve', 'doge', db, str(port)], stdout=log, stderr=log)

def peer(src, rcvbuf=None, timeout=5):
    c = socket.socket()
    if rcvbuf: c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
    c.bind((src, 0)); c.settimeout(timeout); c.connect(('127.0.0.1', port))
    return c
def handshake(c):
    c.sendall(msg('version', version(0))); got = set()
    while not {'version', 'verack'} <= got: got.add(recv_cmd(c)[0])
    c.sendall(msg('verack'))
def ping(c):
    n = os.urandom(8); c.sendall(msg('ping', n)); seen = []
    while True:
        cmd, pl = recv_cmd(c)
        if cmd == 'pong' and pl == n: return seen
        seen.append((cmd, pl))
def spam(c, frame, n):
    c.setblocking(False); sent = 0
    for _ in range(n):
        try: c.sendall(frame); sent += 1
        except (BlockingIOError, socket.timeout, OSError): break
    return sent
def dropped_within(c, secs):
    """drain whatever the server queued; True iff we reach EOF/RST within secs."""
    c.setblocking(True); end = time.time() + secs
    while time.time() < end:
        c.settimeout(max(0.05, end - time.time()))
        try:
            if not c.recv(1 << 20): return True
        except socket.timeout: return False
        except OSError: return True
    return False

try:
    for _ in range(50):
        try: socket.create_connection(('127.0.0.1', port), timeout=1).close(); break
        except OSError: time.sleep(0.1)
    A1 = peer('127.0.0.3', rcvbuf=4096); handshake(A1); ping(A1)
    A2 = peer('127.0.0.4', rcvbuf=4096); handshake(A2); ping(A2)
    n1 = spam(A1, GETDATA, 20); n2 = spam(A2, GETHDRS, 60); t_spam = time.time()
    print('     attackers: A1 sent %d getdata (x%d blocks of %d KiB), A2 sent %d getheaders; neither reads'
          % (n1, NBLK, BLKSZ // 1024, n2), flush=True)
    time.sleep(1.0)
    t0 = time.time()
    try:
        B = peer('127.0.0.5', timeout=4); handshake(B); ping(B); ok = True
    except (OSError, EOFError): ok = False
    ck(ok, 'honest peer handshakes + pings while attackers are not reading (%.2f s)' % (time.time() - t0))
    if ok:
        B.settimeout(30); B.sendall(GETDATA); got = {}
        try:
            seen = ping(B)
            for cmd, pl in seen:
                if cmd == 'block': got[d2(pl[:80])] = pl
        except (OSError, EOFError): pass
        ck(len(got) == NBLK and all(got[h] == raws[h] for h in blk_hashes),
           'honest getdata of %d x %d KiB (%.1f MiB > send queue cap) fully served, intact (%d/%d)'
           % (NBLK, BLKSZ // 1024, NBLK * BLKSZ / 1048576, len(got), NBLK))
    # don't touch the attackers' sockets until the 4 s send-stall bound has
    # certainly elapsed: draining them earlier would make them honest readers
    time.sleep(max(0, t_spam + 7 - time.time()))
    ck(dropped_within(A2, 15), 'getheaders spammer that never reads is disconnected')
    ck(dropped_within(A1, 20), 'getdata spammer that never reads is disconnected (send stall)')
    try:
        C = peer('127.0.0.6', timeout=4); handshake(C); ping(C); ok = True
    except (OSError, EOFError): ok = False
    ck(ok, 'serve plane healthy after the attack (fresh peer handshakes + pings)')
    ck(p.poll() is None, 'serve process still running')
finally:
    p.terminate()
    try: p.wait(5)
    except subprocess.TimeoutExpired: p.kill(); p.wait()
    log.close()
    san = 0
    for l in open(os.path.join(d, 'serve.log'), errors='replace'):
        if 'not reading' in l: print('     log: ' + l.rstrip())
        if 'runtime error' in l or 'Sanitizer' in l: print('     san: ' + l.rstrip()); san += 1
    ck(san == 0, 'no ASan/UBSan reports in the serve log (when built with sanitizers)')
print('serve_noread: ' + ('ALL PASSED' if not fails else '%d FAILED' % fails))
sys.exit(1 if fails else 0)
