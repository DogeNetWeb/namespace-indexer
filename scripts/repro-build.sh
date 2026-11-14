#!/bin/sh
# repro-build.sh — reviewer-reproducible static dnsd from CLEAN git archives.
#
#   scripts/repro-build.sh [--allow-pre-rl] <indexer-commit> [workdir]
#
# dogenet-dns base: DNS_REV, default 72429c7 (the live rate-limiter base).
# The build REFUSES a DNS_REV that lacks the dns_net rate limiter commits
# d8dc8a6, 0056c3c and 72429c7 (e.g. the old 93b52ba snapshot) unless
# --allow-pre-rl is given — a pre-limiter dnsd must never be deployed.
#
# Inputs (env, defaults are the rl-recover layout; repos are only READ via
# `git archive`, never checked out or modified):
#   REPOS=/workspace/rl-recover/b      holds dogenet-dns, dogenet-mesh,
#                                      namespace-protocol, namespace-indexer
#   INDEXER_GIT=$REPOS/namespace-indexer  repo that has <indexer-commit>
#   SECP_GIT=$REPOS/namespace-indexer/vendor/secp256k1  (the submodule pin is
#                                      read from <indexer-commit>'s tree)
#   AM=/workspace/rl-recover/sqlite-amalgamation-3540100
#   DNS_REV=72429c7 MESH_REV=d683004 PROTO_REV=b2f90b5
# Same flags as rl-recover/BUILD.sh (sqlite opts, -O2 -Wall -Wextra -Wshadow,
# -static). Path independence: everything is unpacked under <workdir>
# (default: a fresh mktemp dir) and compiled with -ffile-prefix-map=<workdir>=/build
# (and $AM=/am), so __FILE__ / any embedded path is the same from any directory.
# Untracked files in a working copy can never leak in (git archive only).
# Prints the sha256 of <workdir>/out/dnsd as the last line.
set -eu
ALLOW_PRE_RL=0
if [ "${1:-}" = --allow-pre-rl ]; then ALLOW_PRE_RL=1; shift; fi
REV=${1:?usage: repro-build.sh [--allow-pre-rl] <indexer-commit> [workdir]}
REPOS=${REPOS:-/workspace/rl-recover/b}
INDEXER_GIT=${INDEXER_GIT:-$REPOS/namespace-indexer}
SECP_GIT=${SECP_GIT:-$REPOS/namespace-indexer/vendor/secp256k1}
AM=${AM:-/workspace/rl-recover/sqlite-amalgamation-3540100}
DNS_REV=${DNS_REV:-72429c7} MESH_REV=${MESH_REV:-d683004} PROTO_REV=${PROTO_REV:-b2f90b5}
missing=""
for c in d8dc8a6 0056c3c 72429c7; do
    git -C "$REPOS/dogenet-dns" merge-base --is-ancestor "$c" "$DNS_REV" 2>/dev/null || missing="$missing $c"
done
if [ -n "$missing" ]; then
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" >&2
    echo "!! dogenet-dns $DNS_REV LACKS the rate limiter:$missing" >&2
    echo "!! (live base is 72429c7). This dnsd must not be deployed." >&2
    echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" >&2
    [ "$ALLOW_PRE_RL" = 1 ] || { echo "refusing to build; pass --allow-pre-rl to override" >&2; exit 3; }
    echo "--allow-pre-rl given: building anyway (NOT deployable)" >&2
fi
W=${2:-$(mktemp -d)}; mkdir -p "$W"; W=$(cd "$W" && pwd -P)
[ -z "$(ls -A "$W")" ] || { echo "workdir $W not empty" >&2; exit 2; }
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=0; umask 022
unset MAKEFLAGS MFLAGS CPPFLAGS LDFLAGS || true

S=$W/src; mkdir -p "$S/dogenet-dns" "$S/dogenet-mesh" "$S/namespace-protocol" "$S/namespace-indexer" "$W/out"
git -C "$REPOS/dogenet-dns"        archive "$DNS_REV"   | tar -x -C "$S/dogenet-dns"
git -C "$REPOS/dogenet-mesh"       archive "$MESH_REV"  | tar -x -C "$S/dogenet-mesh"
git -C "$REPOS/namespace-protocol" archive "$PROTO_REV" | tar -x -C "$S/namespace-protocol"
git -C "$INDEXER_GIT"              archive "$REV"       | tar -x -C "$S/namespace-indexer"
SECP_REV=$(git -C "$INDEXER_GIT" rev-parse "$REV:vendor/secp256k1")
git -C "$SECP_GIT" archive "$SECP_REV" | tar -x -C "$S/namespace-indexer/vendor/secp256k1"

MAP="-ffile-prefix-map=$W=/build -ffile-prefix-map=$AM=/am"
mkdir -p "$W/sq"
gcc -O2 $MAP -DSQLITE_DEFAULT_MEMSTATUS=0 -DSQLITE_DQS=0 -DSQLITE_OMIT_LOAD_EXTENSION -c "$AM/sqlite3.c" -o "$W/sq/sqlite3.o"
PP="-std=c11 -D_DEFAULT_SOURCE -O2 -Wall -Wextra $MAP"
CFLAGS="$MAP" make -C "$S/dogenet-mesh" CFLAGS="$PP -Wshadow" ../namespace-indexer/build/secp/lib/libsecp256k1.a -j8 >"$W/build.log" 2>&1
make -C "$S/dogenet-dns" CFLAGS="$PP -Wshadow -I$AM" LIBS="-static $W/sq/sqlite3.o -lpthread -lm" dnsd -j8 >>"$W/build.log" 2>&1
cp "$S/dogenet-dns/dnsd" "$W/out/dnsd"
echo "indexer $(git -C "$INDEXER_GIT" rev-parse "$REV") secp $SECP_REV dns $DNS_REV mesh $MESH_REV proto $PROTO_REV"
echo "gcc: $(gcc --version | head -1)"
sha256sum "$W/out/dnsd" | cut -d' ' -f1
