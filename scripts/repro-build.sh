#!/bin/sh
# repro-build.sh — reviewer-reproducible static dnsd from CLEAN git archives.
#
#   scripts/repro-build.sh <indexer-commit> [workdir]
#
# Inputs (env, defaults are the rl-recover layout; repos are only READ via
# `git archive`, never checked out or modified):
#   REPOS=/workspace/rl-recover/b      holds dogenet-dns, dogenet-mesh,
#                                      namespace-protocol, namespace-indexer
#   INDEXER_GIT=$REPOS/namespace-indexer  repo that has <indexer-commit>
#   SECP_GIT=$REPOS/namespace-indexer/vendor/secp256k1  (the submodule pin is
#                                      read from <indexer-commit>'s tree)
#   AM=/workspace/rl-recover/sqlite-amalgamation-3540100
#   DNS_REV=93b52ba MESH_REV=d683004 PROTO_REV=b2f90b5
# Same flags as rl-recover/BUILD.sh (sqlite opts, -O2 -Wall -Wextra -Wshadow,
# -static). Path independence: everything is unpacked under <workdir>
# (default: a fresh mktemp dir) and compiled with -ffile-prefix-map=<workdir>=/build
# (and $AM=/am), so __FILE__ / any embedded path is the same from any directory.
# Untracked files in a working copy can never leak in (git archive only).
# Prints the sha256 of <workdir>/out/dnsd as the last line.
set -eu
REV=${1:?usage: repro-build.sh <indexer-commit> [workdir]}
REPOS=${REPOS:-/workspace/rl-recover/b}
INDEXER_GIT=${INDEXER_GIT:-$REPOS/namespace-indexer}
SECP_GIT=${SECP_GIT:-$REPOS/namespace-indexer/vendor/secp256k1}
AM=${AM:-/workspace/rl-recover/sqlite-amalgamation-3540100}
DNS_REV=${DNS_REV:-93b52ba} MESH_REV=${MESH_REV:-d683004} PROTO_REV=${PROTO_REV:-b2f90b5}
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
