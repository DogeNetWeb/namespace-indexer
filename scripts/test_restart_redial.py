#!/usr/bin/env python3
# A restarted node must redial its configured peer (run under `unshare -rn`).
# An embedder (dogenet-dnsd) builds the dial list as its --peer args followed
# by the "/dogenet-" rows of the peers table, so after a first run the SAME
# addr is listed twice. Those two configured seats used to park behind each
# other forever (each saw the other's disconnected seat as "live") and the
# restarted node never dialled. Also covered: a hostname seed + its numeric
# row (localhost / 127.0.0.1), which only collide after resolution.
# Each case: run, handshake, kill, restart on the same db; the restarted node
# must connect within N s (first dial tick is +5 s).
import hashlib, os, socket, sqlite3, struct, subprocess, sys, tempfile, time
IDX = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'indexerd')
N = 15
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

def run_case(name, dial_fmt, k):
    d = tempfile.mkdtemp(); db = os.path.join(d, 'db1')
    s = sqlite3.connect(os.path.join(d, 'serve-doge.db'))
    s.executescript("CREATE TABLE headers(height INTEGER PRIMARY KEY, hash BLOB, hdr BLOB);"
                    "CREATE INDEX headers_hash ON headers(hash);"); s.commit(); s.close()
    lst = socket.socket(); lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lst.bind(('127.0.0.1', 0)); lst.listen(4)
    fport = lst.getsockname()[1]
    port = 22000 + (os.getpid() + k) % 2000
    dial = dial_fmt % {'p': fport}
    for run in ('first run', 'restart'):
        p = subprocess.Popen([IDX, 'serve', 'doge', db, str(port), dial],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        t0 = time.time(); lst.settimeout(N); got = None; c = None
        try:
            c, _ = lst.accept(); got = time.time() - t0
            c.settimeout(5)
            try:
                while True:
                    cmd, pl = recv_cmd(c)
                    if cmd == 'version':
                        c.sendall(msg('version', version(1)) + msg('verack')); break
            except (OSError, EOFError): pass
            time.sleep(1.5)                     # let it hold the session
        except socket.timeout: pass
        finally:
            p.terminate(); p.wait(5)
            if c: c.close()
        ck(got is not None, '%s: %s dials within %d s%s' % (name, run, N, '' if got is None else ' (%.1f s)' % got))
        time.sleep(0.5)
    lst.close()

run_case('same addr listed twice', '127.0.0.1:%(p)d,127.0.0.1:%(p)d', 0)
run_case('hostname + numeric row', 'localhost:%(p)d,127.0.0.1:%(p)d', 1)
run_case('numeric row + hostname', '127.0.0.1:%(p)d,localhost:%(p)d', 2)
sys.exit(1 if fails else 0)
