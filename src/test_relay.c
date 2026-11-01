// test_relay.c — outbound redial backoff policy (pure helpers).
#include "relay_policy.h"
#include <stdio.h>
#include <string.h>

static int fails;
#define CK(c, m) do { if (c) printf("ok   %s\n", m); else { printf("FAIL %s\n", m); fails++; } } while (0)

int main(void) {
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
