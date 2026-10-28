#!/bin/sh
# Serve-plane dial tests, in a private user+net+mount namespace (no real
# network, never touches ~/.pepenet or the live ports).
#  1. same-IP seats: two configured peers on ONE ip (different ports) — exactly
#     one connects (one-connection-per-IP rule), and nothing deadlocks.
#  2. multi-address name: a name resolving to [::1] (dead) then 127.0.0.1
#     (live) still connects — the dialer walks every getaddrinfo result.
#  3. a comma list of two peers on DIFFERENT ips — both connect.
# usage: test_dial_peers.sh ./indexerd
set -u
BIN=$(readlink -f "${1:-./indexerd}")
if [ -z "${IN_NS:-}" ]; then
    exec env IN_NS=1 unshare -rnm sh "$(readlink -f "$0")" "$BIN"
fi
ip link set lo up
T=$(mktemp -d); cd "$T" || exit 1
printf '::1 multi.test\n127.0.0.1 multi.test\n' > hosts
mount --bind "$T/hosts" /etc/hosts || { echo "FAIL: cannot bind /etc/hosts"; exit 1; }
first=$(getent ahosts multi.test | awk 'NR==1{print $1}')
rc=0
ok()  { echo "ok   $*"; }
bad() { echo "FAIL $*"; rc=1; }
P=19731
IDX_IPV6=0 "$BIN" serve regtest a.db $P          > a.log 2>&1 & PIDS="${PIDS:-} $!"
IDX_IPV6=0 "$BIN" serve regtest b.db $((P+1))    > b.log 2>&1 & PIDS="${PIDS:-} $!"
sleep 2
"$BIN" serve regtest c.db $((P+3)) "127.0.0.1:$P,127.0.0.1:$((P+1))"  > c.log 2>&1 & PIDS="${PIDS:-} $!"
"$BIN" serve regtest d.db $((P+4)) "multi.test:$P"                   > d.log 2>&1 & PIDS="${PIDS:-} $!"
ip addr add 127.0.0.2/8 dev lo 2>/dev/null
"$BIN" serve regtest e.db $((P+5)) "127.0.0.1:$P,127.0.0.2:$((P+1))" > e.log 2>&1 & PIDS="${PIDS:-} $!"
sleep 18
kill $PIDS 2>/dev/null; sleep 1; kill -9 $PIDS 2>/dev/null; wait 2>/dev/null
n=$(grep -c '^serve: dialed 127.0.0.1:' c.log)
[ "$n" = 1 ] && ok "same-ip: exactly one of two seats connected" \
             || { bad "same-ip: $n connections (want 1)"; cat c.log; }
[ "$first" = "::1" ] || bad "multi.test resolves $first first (want ::1)"
grep -q "^serve: dialed 127.0.0.1:$P" d.log && ok "multi-addr: dead ::1 first, connected via 127.0.0.1" \
    || { bad "multi-addr: no connect"; cat d.log; }
[ "$(grep -c '^serve: dialed' e.log)" = 2 ] && ok "comma list, two ips: both connected" \
    || { bad "comma list, two ips"; cat e.log; }
cd /; rm -rf "$T"
exit $rc
