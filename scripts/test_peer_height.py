#!/usr/bin/env python3
# peer_height follows peer announcements over the wire (run under unshare -rn).
# A fake peer handshakes with `indexerd serve doge`, then announces via inv /
# headers / block; the node's meta peer_height must rise to the announced
# height (first write is immediate; serve exit flushes) and never fall.
import hashlib, os, socket, sqlite3, struct, subprocess, sys, tempfile, time
IDX = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', 'indexerd')
MAGIC = bytes([0xC0, 0xC0, 0xC0, 0xC0])
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
def hdr(prev, ver=4):
    return struct.pack('<i', ver) + prev + os.urandom(32) + struct.pack('<III', 0, 0, 0)
X, Y = os.urandom(32), os.urandom(32)          # store: X @ 777, Y @ 5
def run(name, msgs, want, preset=None):
    d = tempfile.mkdtemp(); db = os.path.join(d, 'db1')
    s = sqlite3.connect(os.path.join(d, 'serve-doge.db'))
    s.executescript("CREATE TABLE headers(height INTEGER PRIMARY KEY, hash BLOB, hdr BLOB);"
                    "CREATE INDEX headers_hash ON headers(hash);")
    s.execute("INSERT INTO headers VALUES(777,?,?)", (X, hdr(bytes(32))))
    s.execute("INSERT INTO headers VALUES(5,?,?)", (Y, hdr(bytes(32)))); s.commit(); s.close()
    port = 18000 + (os.getpid() + len(name)) % 2000
    p = subprocess.Popen([IDX, 'serve', 'doge', db, str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try: c = socket.create_connection(('127.0.0.1', port), 1); break
            except OSError: time.sleep(0.05)
        else: ck(False, name + ': serve listening'); return
        if preset is not None:
            time.sleep(0.2)
            m = sqlite3.connect(db); m.execute("INSERT OR REPLACE INTO meta(k,v) VALUES('peer_height',?)", (preset,)); m.commit(); m.close()
        c.sendall(msg('version', version(3)) + msg('verack'))
        time.sleep(0.4)
        for cmd, pl in msgs: c.sendall(msg(cmd, pl))
        time.sleep(0.6); c.close()
    finally:
        p.terminate(); p.wait(5)
    m = sqlite3.connect(db); r = m.execute("SELECT v FROM meta WHERE k='peer_height'").fetchone(); m.close()
    got = int(r[0]) if r else None
    ck(got == want, '%s: peer_height %s (want %s)' % (name, got, want))
inv = lambda h: b'\x01' + struct.pack('<I', 2) + h
run('inv of a known block', [('inv', inv(X))], 777)
run('pushed block on a known tip', [('block', hdr(X) + b'\x00')], 778)
run('headers run: known then child', [('headers', b'\x02' + hdr(bytes(32)) + b'\x00' + hdr(X) + b'\x00')], 778)
run('unknown inv/headers ignored', [('inv', inv(os.urandom(32))), ('headers', b'\x01' + hdr(os.urandom(32)) + b'\x00')], None)
run('AuxPoW header stops the headers walk', [('headers', b'\x02' + hdr(Y, 0x104) + b'\x00' + hdr(X) + b'\x00')], 6)
run('never lowered by a lower announcement', [('inv', inv(Y))], 900, preset=900)
sys.exit(1 if fails else 0)
