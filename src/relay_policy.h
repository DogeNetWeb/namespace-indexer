// relay_policy.h — local relay policy helpers for the serve loop (no wire or
// on-chain format change). Pure functions so test_relay can pin them.
//
//  • BIP133 feefilter: a peer that sent `feefilter` (int64 LE, koinu per 1000
//    bytes) does not want txs below that rate. Dogecoin Core peers enforce it
//    by rejecting with 0x42 "rate limited free transaction" and then evicting
//    us, so we must not inv/serve such txs to them. A tx whose fee we cannot
//    determine (inputs not in our pool) counts as below any nonzero filter.
//  • Outbound redial after a drop: exponential backoff with jitter, capped,
//    reset once a session stayed up long enough to count as healthy.
#ifndef RELAY_POLICY_H
#define RELAY_POLICY_H
#include <stdint.h>
#include <stddef.h>

#define REDIAL_BASE_S     15      // first retry (was the fixed now+15)
#define REDIAL_CAP_S      1800    // 30 min ceiling
#define REDIAL_HEALTHY_S  600     // a session up >= 10 min resets the backoff
#define FEEFILTER_MAX     ((int64_t)1e17)  // > MAX_MONEY per kB: treat as "relay nothing"

// parse a feefilter payload; returns the rate (>= 0) or -1 if malformed
static inline int64_t feefilter_parse(const uint8_t *pl, size_t n) {
    if (n != 8) return -1;
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | pl[i];
    int64_t r = (int64_t)v;
    if (r < 0) return -1;
    return r > FEEFILTER_MAX ? FEEFILTER_MAX : r;
}
// koinu per 1000 bytes, rounded down; -1 if unknown
static inline int64_t feerate_per_kb(int64_t fee, size_t len) {
    if (fee < 0 || len == 0) return -1;
    return (int64_t)(((__int128)fee * 1000) / (int64_t)len);
}
// may a tx with this rate (-1 = unknown) be relayed to a peer with this filter?
static inline int feefilter_allows(int64_t filter, int64_t rate) {
    if (filter <= 0) return 1;
    return rate >= 0 && rate >= filter;
}
// delay before the next redial given consecutive failed/short sessions
// (fails >= 1) and a random word; result in [base, base*1.25], <= cap*1.25
static inline uint32_t redial_delay(int fails, uint32_t rnd) {
    if (fails < 1) fails = 1;
    uint32_t d = REDIAL_BASE_S;
    for (int i = 1; i < fails && d < REDIAL_CAP_S; i++) d *= 2;
    if (d > REDIAL_CAP_S) d = REDIAL_CAP_S;
    return d + (d / 4 ? rnd % (d / 4 + 1) : 0);
}
// update the failure count when a session ends; up_for < 0 = never came up
static inline int redial_next_fails(int fails, long up_for) {
    if (up_for >= REDIAL_HEALTHY_S) return 1;     // healthy: back to the base delay
    return fails < 30 ? fails + 1 : 30;
}
#endif
