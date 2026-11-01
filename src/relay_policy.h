// relay_policy.h — local relay policy helpers for the serve loop (no wire or
// on-chain format change). Pure functions so test_relay can pin them.
//
//  • Outbound redial after a drop: exponential backoff with jitter, capped,
//    reset once a session stayed up long enough to count as healthy.
#ifndef RELAY_POLICY_H
#define RELAY_POLICY_H
#include <stdint.h>
#include <stddef.h>

#define REDIAL_BASE_S     15      // first retry (was the fixed now+15)
#define REDIAL_CAP_S      1800    // 30 min ceiling
#define REDIAL_HEALTHY_S  600     // a session up >= 10 min resets the backoff

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
