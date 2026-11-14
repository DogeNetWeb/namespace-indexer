#!/usr/bin/env python3
# Outbound redial backs off over the wire (run under `unshare -rn`).
# `indexerd serve doge` is given one configured peer: a fake node that
# completes the version/verack handshake and then evicts us (FIN) — what a
# Core peer does after a 0x42 reject. The gaps between successive dials must
# GROW (15 s base, x2 per short session, +0..25% jitter, 5 s dial tick), where
# the old fixed `now + 15` gave equal ~15-20 s gaps forever. ~60 s runtime.
# A second configured peer points at a CLOSED port (connect refused, RST):
# its dial attempts are timed by sniffing the SYNs on lo (AF_PACKET; we hold
# CAP_NET_RAW inside the user netns) and those gaps must grow too (the
# dial-failure path, not the short-session path).
# Ceiling: REDIAL_CAP_S 1800 s + up to 25% jitter = 2250 s (~37.5 min).
import threading, hashlib, os, socket, sqlite3, struct, subprocess, sys, tempfile, time
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

d = tempfile.mkdtemp(); db = os.path.join(d, 'db1')
s = sqlite3.connect(os.path.join(d, 'serve-doge.db'))
s.executescript("CREATE TABLE headers(height INTEGER PRIMARY KEY, hash BLOB, hdr BLOB);"
                "CREATE INDEX headers_hash ON headers(hash);"); s.commit(); s.close()
lst = socket.socket(); lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
lst.bind(('127.0.0.1', 0)); lst.listen(4); lst.settimeout(70)
fport = lst.getsockname()[1]
port = 20000 + os.getpid() % 2000
probe = socket.socket(); probe.bind(('127.0.0.3', 0)); rport = probe.getsockname()[1]; probe.close()  # closed port
syns = []
sn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)); sn.bind(('lo', 0)); sn.settimeout(1)
stop = []
def sniff():
    while not stop:
        try: pkt, a = sn.recvfrom(65535)
        except socket.timeout: continue
        if a[2] == 4: continue                                  # PACKET_OUTGOING: lo shows each packet twice
        ip = pkt[14:]
        if len(ip) < 40 or ip[0] >> 4 != 4 or ip[9] != 6 or ip[16:20] != bytes([127, 0, 0, 3]): continue
        t = ip[(ip[0] & 15) * 4:]
        if struct.unpack('>H', t[2:4])[0] == rport and t[13] & 0x12 == 0x02: syns.append(time.time())
th = threading.Thread(target=sniff, daemon=True); th.start()
p = subprocess.Popen([IDX, 'serve', 'doge', db, str(port), '127.0.0.1:%d,127.0.0.3:%d' % (fport, rport)],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
times = []
try:
    t0 = time.time()
    while len(times) < 3 and time.time() - t0 < 110:
        try: c, _ = lst.accept()
        except socket.timeout: break
        times.append(time.time())
        c.settimeout(5)
        try:
            while True:
                cmd, pl = recv_cmd(c)
                if cmd == 'version':
                    c.sendall(msg('version', version(1)) + msg('verack')); break
        except (OSError, EOFError): pass
        time.sleep(0.3); c.close()                       # evict: short session
    while len(syns) < 3 and time.time() - t0 < 110: time.sleep(0.5)
finally:
    p.terminate(); p.wait(5); lst.close(); stop.append(1)
ck(len(times) == 3, 'three dials observed (got %d)' % len(times))
if len(times) == 3:
    g1, g2 = times[1] - times[0], times[2] - times[1]
    print('     gaps: %.1f s, %.1f s' % (g1, g2))
    ck(14 <= g1 <= 25, 'first redial after a short session ~15 s (+jitter, tick)')
    ck(g2 >= 29, 'second redial backed off to >= 30 s')
    ck(g2 > g1 + 8, 'redial delay grows across repeated drops')
ck(len(syns) >= 3, 'three refused dials observed (got %d)' % len(syns))
if len(syns) >= 3:
    f1, f2 = syns[1] - syns[0], syns[2] - syns[1]
    print('     refused gaps: %.1f s, %.1f s' % (f1, f2))
    ck(14 <= f1 <= 25, 'first retry after a refused connect ~15 s')
    ck(f2 >= 29, 'second retry after a refused connect backed off to >= 30 s')
    ck(f2 > f1 + 8, 'dial-failure delay grows across repeated refusals')
sys.exit(1 if fails else 0)
