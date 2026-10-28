// netaddr.h — IPv4+IPv6 address text, policy and dual-stack listen (local only;
// the wire's 16-byte addr field already carries both). Same code as pepenet
// indexer/src/net_policy.c na_* helpers.
#ifndef IDX_NETADDR_H
#define IDX_NETADDR_H
#include <stddef.h>
#include <stdint.h>
/* ── addresses (IPv4 + IPv6; local only — the wire already carries 16 bytes) ──
 * Text form stored in peers.addr / used for dialing:
 *   IPv4  "a.b.c.d:port"          (unchanged; v4-mapped v6 always normalizes here)
 *   IPv6  "[2001:db8::1]:port"    (brackets: an old binary's strrchr(':') split
 *                                  then sees a non-numeric host and drops the row)
 */
#define NA_HOST_MAX 64
/* split "host[:port]", "[v6]:port", "[v6]" or a bare v6 literal. */
void na_split(const char *s, char *host, size_t cap, uint16_t *port, uint16_t dflt);
/* host + port → canonical text (brackets iff host has a ':'). */
void na_join(char *out, size_t cap, const char *host, unsigned port);
/* 16-byte wire ip → host text; v4-mapped → dotted quad. Returns 4 or 6. */
int  na_from16(const uint8_t ip[16], char *host, size_t cap);
/* numeric host text → 16-byte wire ip (v4 → ::ffff:a.b.c.d). 0 = not numeric. */
int  na_to16(const char *host, uint8_t ip[16]);
/* canonicalize a numeric host (::ffff:1.2.3.4 → 1.2.3.4, v6 compressed). 0 = not numeric. */
int  na_canon(const char *host, char *out, size_t cap);
/* 1 = globally routable unicast worth storing/dialing/advertising. */
int  na_routable16(const uint8_t ip[16]);
int  na_routable(const char *host);
/* netgroup key for eclipse diversity: v4 /16 "a.b", v6 /32 "v6:xxxx:xxxx", else host. */
void na_group(const char *host, char *out, size_t cap);
/* sockaddr (v4, v6 or mapped) → canonical host text + port. 0 on other families. */
struct sockaddr;
int  na_sockaddr(const struct sockaddr *sa, char *host, size_t cap, unsigned *port);
/* TCP listen on all interfaces. Dual-stack first (AF_INET6, IPV6_V6ONLY=0, ::);
 * if that fails — no IPv6 in the kernel, disabled, EAFNOSUPPORT — log and fall
 * back to AF_INET 0.0.0.0. allow_v6=0 (env IDX_IPV6=0) forces v4 only.
 * *fam_out = 6 dual-stack, 4 v4-only. Returns fd or -1. One fd either way. */
int  na_listen_any(uint16_t port, int backlog, int allow_v6, int *fam_out);
/* ban/cap key. v4 (incl. ::ffff:-mapped) → exact dotted quad (unchanged);
 * v6 → prefix key "v6/64:xxxx:xxxx:xxxx:xxxx" (v6bits 64) or "v6/48:…" (48);
 * non-numeric → the text as-is. Returns 4, 6 or 0. */
int  na_key(const char *host, int v6bits, char *out, size_t cap);
int  na_same_key(const char *a, const char *b, int v6bits);  /* 1 = same key */
/* Self-advertise of our own IPv6 is opt-in: --advertise-v6 or IDX_ADVERTISE_V6=1.
 * Listening dual-stack is unaffected; only which self address we gossip. */
int  na_advertise_v6(void);
void na_set_advertise_v6(int on);
int  na_self_advertisable(const char *hostport);          /* v4 → 1; v6 → opt-in */
int  na_ipv6_allowed(void);                              /* env IDX_IPV6 != "0" */

#endif
