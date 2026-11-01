// test_relay.c — BIP133 feefilter relay policy, mempool fee rates, outbound
// redial backoff (pure helpers + mempool; the wire paths are scripts/test_*.py).
#include "relay_policy.h"
#include "mempool.h"
#include "chain.h"
#include <stdio.h>
#include <string.h>

static int fails;
#define CK(c, m) do { if (c) printf("ok   %s\n", m); else { printf("FAIL %s\n", m); fails++; } } while (0)

static void le(uint8_t *p, uint64_t v, int n) { for (int i = 0; i < n; i++) p[i] = (uint8_t)(v >> (8 * i)); }
// n-in 1-out legacy tx (inputs prev:vout0..n-1), P2PKH-shaped output, 1-byte scriptSig
static size_t mktxn(uint8_t *b, const uint8_t prev[32], int nin, int64_t value) {
    size_t o = 0;
    le(b + o, 1, 4); o += 4; b[o++] = (uint8_t)nin;
    for (int i = 0; i < nin; i++) {
        memcpy(b + o, prev, 32); o += 32; le(b + o, (uint64_t)i, 4); o += 4;
        b[o++] = 1; b[o++] = 0x51;                   // scriptSig: OP_TRUE
        le(b + o, 0xffffffff, 4); o += 4;
    }
    b[o++] = 1;
    le(b + o, (uint64_t)value, 8); o += 8;
    b[o++] = 25; b[o++] = 0x76; b[o++] = 0xa9; b[o++] = 20; memset(b + o, 0x11, 20); o += 20; b[o++] = 0x88; b[o++] = 0xac;
    le(b + o, 0, 4); o += 4;
    return o;
}
static size_t mktx(uint8_t *b, const uint8_t prev[32], int64_t value) { return mktxn(b, prev, 1, value); }
// 1-in 4-out parent: four 1-DOGE outputs
static size_t mkfan(uint8_t *b, const uint8_t prev[32]) {
    size_t o = 0;
    le(b + o, 1, 4); o += 4; b[o++] = 1;
    memcpy(b + o, prev, 32); o += 32; le(b + o, 0, 4); o += 4;
    b[o++] = 1; b[o++] = 0x51; le(b + o, 0xffffffff, 4); o += 4;
    b[o++] = 4;
    for (int k = 0; k < 4; k++) {
        le(b + o, 100000000, 8); o += 8;
        b[o++] = 25; b[o++] = 0x76; b[o++] = 0xa9; b[o++] = 20; memset(b + o, 0x20 + k, 20); o += 20; b[o++] = 0x88; b[o++] = 0xac;
    }
    le(b + o, 0, 4); o += 4;
    return o;
}

int main(void) {
    // feefilter payload parsing + policy
    uint8_t pl[8]; le(pl, 50000000, 8);
    CK(feefilter_parse(pl, 8) == 50000000, "feefilter 50M koinu/kB parses (192.0.2.1's value)");
    CK(feefilter_parse(pl, 7) == -1, "short feefilter payload rejected");
    le(pl, 0x8000000000000000ull, 8);
    CK(feefilter_parse(pl, 8) == -1, "negative feefilter rejected");
    le(pl, 0x7fffffffffffffffull, 8);
    CK(feefilter_parse(pl, 8) == FEEFILTER_MAX, "huge feefilter clamps");
    CK(feerate_per_kb(1000, 250) == 4000, "fee 1000 over 250 B = 4000/kB");
    CK(feerate_per_kb(-1, 250) == -1, "unknown fee -> unknown rate");
    CK(feefilter_allows(0, -1), "no filter: relay anything");
    CK(feefilter_allows(1000, -1), "filter set: UNKNOWN-rate tx is still relayed (no UTXO set)");
    CK(feefilter_allows(1, -1) && feefilter_allows(FEEFILTER_MAX, -1), "unknown relayed under any filter (no feefilter=1 fingerprint)");
    CK(feefilter_allows(1000, 1000), "rate == filter relayed");
    CK(!feefilter_allows(1000, 999), "rate known below filter held back");

    // mempool fee rate: known only from in-pool parents
    mempool_reset();
    uint8_t ext[32]; memset(ext, 0xab, 32);
    uint8_t p[512], ch[512], pid[32], cid[32]; char why[128];
    size_t pn = mktx(p, ext, 100000000);
    int ap = mempool_accept(p, pn, pid, why, sizeof why);
    if (!ap) printf("     parent reject: %s\n", why);
    CK(ap, "parent accepted");
    CK(mempool_feerate(pid) == -1, "parent spends a confirmed outpoint -> rate unknown");
    size_t cn = mktx(ch, pid, 100000000 - 1000);
    int ac = mempool_accept(ch, cn, cid, why, sizeof why);
    CK(ac, "child accepted");
    int64_t want = feerate_per_kb(1000, cn);
    CK(mempool_feerate(cid) == want, "child rate = (in - out)*1000/len from the pooled parent");
    CK(!feefilter_allows(50000000, mempool_feerate(cid)), "child known below a 50M/kB filter -> held back");
    CK(feefilter_allows(want, mempool_feerate(cid)), "child at the peer's filter -> relayed");
    uint8_t none[32]; memset(none, 0xcd, 32);
    CK(mempool_feerate(none) == -1, "tx not in pool -> unknown");
    mempool_reset();

    // orphan child first, parent second: the child's rate is recomputed
    pn = mktx(p, ext, 100000000);
    { IdxTx t; if (idx_tx_parse(p, pn, &t)) { memcpy(pid, t.txid, 32); idx_tx_free(&t); } }
    cn = mktx(ch, pid, 100000000 - 1000);
    CK(mempool_accept(ch, cn, cid, why, sizeof why), "orphan child accepted first");
    CK(mempool_feerate(cid) == -1, "orphan child: rate unknown while the parent is absent");
    CK(mempool_accept(p, pn, pid, why, sizeof why), "parent arrives");
    CK(mempool_feerate(cid) == feerate_per_kb(1000, cn), "orphan child's rate recomputed when its parent is accepted");
    mempool_reset();

    // multi-input child spending one parent 4x: rate from stored output values
    uint8_t fan[512], fid[32];
    size_t fnn = mkfan(fan, ext);
    CK(mempool_accept(fan, fnn, fid, why, sizeof why), "fan-out parent accepted");
    cn = mktxn(ch, fid, 4, 400000000 - 5000);
    CK(mempool_accept(ch, cn, cid, why, sizeof why), "4-input child accepted");
    CK(mempool_feerate(cid) == feerate_per_kb(5000, cn), "4-input child rate from the parent's stored outputs");
    mempool_reset();

    // redial backoff
    CK(redial_delay(1, 0) == REDIAL_BASE_S, "first redial = base 15 s (old behaviour)");
    CK(redial_delay(2, 0) == 30 && redial_delay(3, 0) == 60, "doubles per short session");
    CK(redial_delay(30, 0) == REDIAL_CAP_S, "capped at 1800 s");
    int jit_ok = 1;
    for (uint32_t r = 0; r < 5000; r += 7) { uint32_t d = redial_delay(4, r * 2654435761u); if (d < 120 || d > 150) jit_ok = 0; }
    CK(jit_ok, "jitter stays within [d, 1.25·d]");
    CK(redial_delay(30, 0xffffffffu) <= REDIAL_CAP_S + REDIAL_CAP_S / 4, "jittered cap bounded");
    int f = 0;
    for (int i = 0; i < 4; i++) f = redial_next_fails(f, 120);   // evicted after 2 min, 4 times
    CK(f == 4 && redial_delay(f, 0) == 120, "4 short sessions → 120 s");
    CK(redial_next_fails(f, -1) == 5, "dial/handshake failure counts as a failed session");
    CK(redial_next_fails(f, REDIAL_HEALTHY_S) == 1, "healthy session resets to base");
    f = 0; for (int i = 0; i < 1000; i++) f = redial_next_fails(f, 0);
    CK(f == 30 && redial_delay(f, 0) == REDIAL_CAP_S, "exponent saturates (no overflow)");

    printf("test_relay: %s (%d failure%s)\n", fails ? "FAILED" : "ALL PASSED", fails, fails == 1 ? "" : "s");
    return fails != 0;
}
