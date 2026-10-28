// netaddr.c — see netaddr.h.
#include "netaddr.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// ── addresses ────────────────────────────────────────────────────────────────
void na_split(const char *s, char *host, size_t cap, uint16_t *port, uint16_t dflt) {
    *port = dflt;
    if (!s) { if (cap) host[0] = 0; return; }
    if (s[0] == '[') {                                   // "[v6]" or "[v6]:port"
        const char *e = strchr(s, ']');
        if (!e) { snprintf(host, cap, "%s", s); return; }
        snprintf(host, cap, "%.*s", (int)(e - s - 1), s + 1);
        if (e[1] == ':' && e[2] && strspn(e + 2, "0123456789") == strlen(e + 2)) *port = (uint16_t)atoi(e + 2);
        return;
    }
    snprintf(host, cap, "%s", s);
    char *c = strchr(host, ':');
    if (c && strchr(c + 1, ':')) return;                 // bare v6 literal: no port
    if (c && c[1] && strspn(c + 1, "0123456789") == strlen(c + 1)) { *c = 0; *port = (uint16_t)atoi(c + 1); }
}
void na_join(char *out, size_t cap, const char *host, unsigned port) {
    if (strchr(host, ':')) snprintf(out, cap, "[%s]:%u", host, port);
    else                   snprintf(out, cap, "%s:%u", host, port);
}
static const uint8_t k_v4map[12] = { 0,0,0,0,0,0,0,0,0,0,0xFF,0xFF };
int na_from16(const uint8_t ip[16], char *host, size_t cap) {
    if (!memcmp(ip, k_v4map, 12)) { snprintf(host, cap, "%u.%u.%u.%u", ip[12], ip[13], ip[14], ip[15]); return 4; }
    char b[INET6_ADDRSTRLEN]; if (!inet_ntop(AF_INET6, ip, b, sizeof b)) b[0] = 0;
    snprintf(host, cap, "%s", b); return 6;
}
int na_to16(const char *host, uint8_t ip[16]) {
    struct in_addr a4; struct in6_addr a6;
    if (inet_pton(AF_INET, host, &a4) == 1) { memcpy(ip, k_v4map, 12); memcpy(ip + 12, &a4, 4); return 4; }
    if (inet_pton(AF_INET6, host, &a6) == 1) { memcpy(ip, &a6, 16); return memcmp(ip, k_v4map, 12) ? 6 : 4; }
    return 0;
}
int na_canon(const char *host, char *out, size_t cap) {
    uint8_t ip[16]; if (!na_to16(host, ip)) return 0;
    return na_from16(ip, out, cap);
}
int na_routable16(const uint8_t ip[16]) {
    if (!memcmp(ip, k_v4map, 12)) {                      // IPv4 — same rules as before
        unsigned a = ip[12], b = ip[13];
        if (!a || a == 127 || a == 10 || a >= 224) return 0;
        if (a == 169 && b == 254) return 0;
        if (a == 172 && b >= 16 && b <= 31) return 0;
        if (a == 192 && b == 168) return 0;
        return 1;
    }
    if ((ip[0] & 0xE0) != 0x20) return 0;                // only 2000::/3 global unicast
    // (this alone excludes ::, ::1, IPv4-compat, ULA fc00::/7, link-local
    //  fe80::/10, site-local fec0::/10, multicast ff00::/8, 64:ff9b::/96 NAT64,
    //  100::/64 discard)
    if (ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8) return 0;  // 2001:db8::/32 doc
    if (ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x00 && ip[3] == 0x00) return 0;  // 2001::/32 Teredo
    if (ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x00 && (ip[3] & 0xF0) == 0x10) return 0; // 2001:10::/28 ORCHID
    if (ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x00 && (ip[3] & 0xF0) == 0x20) return 0; // 2001:20::/28 ORCHIDv2
    if (ip[0] == 0x20 && ip[1] == 0x02) return 0;        // 2002::/16 6to4 (relay-dependent)
    if (ip[0] == 0x3f && ip[1] == 0xff) return 0;        // 3fff::/20 doc (RFC 9637)
    return 1;
}
int na_routable(const char *host) {
    uint8_t ip[16]; return na_to16(host, ip) ? na_routable16(ip) : 0;
}
void na_group(const char *host, char *out, size_t cap) {
    uint8_t ip[16]; int f = na_to16(host, ip);
    if (f == 4)      snprintf(out, cap, "%u.%u", ip[12], ip[13]);
    else if (f == 6) snprintf(out, cap, "v6:%02x%02x:%02x%02x", ip[0], ip[1], ip[2], ip[3]);
    else             snprintf(out, cap, "%s", host);
}
int na_sockaddr(const struct sockaddr *sa, char *host, size_t cap, unsigned *port) {
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)sa;
        uint8_t ip[16]; memcpy(ip, k_v4map, 12); memcpy(ip + 12, &s4->sin_addr, 4);
        na_from16(ip, host, cap);
        if (port) *port = ntohs(s4->sin_port);
        return 4;
    }
    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;
        int f = na_from16((const uint8_t *)&s6->sin6_addr, host, cap);
        if (port) *port = ntohs(s6->sin6_port);
        return f;
    }
    return 0;
}
int na_ipv6_allowed(void) {
    const char *e = getenv("IDX_IPV6");
    return !(e && !strcmp(e, "0"));
}
int na_listen_any(uint16_t port, int backlog, int allow_v6, int *fam_out) {
    int yes = 1, no = 0;
    if (allow_v6) {
        int fd = socket(AF_INET6, SOCK_STREAM, 0);
        if (fd >= 0) {
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&yes, sizeof yes);
            struct sockaddr_in6 s6; memset(&s6, 0, sizeof s6);
            s6.sin6_family = AF_INET6; s6.sin6_addr = in6addr_any; s6.sin6_port = htons(port);
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const void *)&no, sizeof no) == 0 &&
                bind(fd, (struct sockaddr *)&s6, sizeof s6) == 0 && listen(fd, backlog) == 0) {
                if (fam_out) *fam_out = 6;
                return fd;
            }
            int e = errno; close(fd);
            // EADDRINUSE is the port, not the family: v4 would hit it too, and the
            // caller's "already in use" path must see that errno.
            if (e == EADDRINUSE) { errno = e; return -1; }
            fprintf(stderr, "listen: dual-stack [::]:%u failed (%s) — falling back to IPv4 only\n", port, strerror(e));
        } else {
            fprintf(stderr, "listen: no IPv6 socket (%s) — IPv4 only on port %u\n", strerror(errno), port);
        }
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&yes, sizeof yes);
    struct sockaddr_in sa; memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET; sa.sin_addr.s_addr = INADDR_ANY; sa.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(fd, backlog) != 0) {
        int e = errno; close(fd); errno = e; return -1;
    }
    if (fam_out) *fam_out = 4;
    return fd;
}

// ── ban/cap keys + self-advertise gate (local policy only; no wire change) ──
// IPv4 (and ::ffff:-mapped) keys on the exact address, as before. IPv6 keys on
// a prefix: one /64 is one end site (SLAAC/privacy rotate the low 64 bits
// freely), so bans and per-host caps must not hand out a slot per /128.
int na_key(const char *host, int v6bits, char *out, size_t cap) {
    uint8_t ip[16]; int f = host ? na_to16(host, ip) : 0;
    if (f == 4) { snprintf(out, cap, "%u.%u.%u.%u", ip[12], ip[13], ip[14], ip[15]); return 4; }
    if (f == 6) {
        int nb = v6bits == 48 ? 6 : 8;
        int o = snprintf(out, cap, "v6/%d:", nb * 8);
        for (int i = 0; i < nb && o > 0 && (size_t)o < cap; i += 2)
            o += snprintf(out + o, cap - (size_t)o, "%s%02x%02x", i ? ":" : "", ip[i], ip[i + 1]);
        return 6;
    }
    snprintf(out, cap, "%s", host ? host : ""); return 0;
}
int na_same_key(const char *a, const char *b, int v6bits) {
    if (!a || !b || !*a || !*b) return 0;
    char ka[NA_HOST_MAX], kb[NA_HOST_MAX];
    na_key(a, v6bits, ka, sizeof ka); na_key(b, v6bits, kb, sizeof kb);
    return !strcmp(ka, kb);
}
static int g_adv_v6 = -1;                                 // -1 = read env once
void na_set_advertise_v6(int on) { g_adv_v6 = on ? 1 : 0; }
int na_advertise_v6(void) {
    if (g_adv_v6 < 0) { const char *e = getenv("IDX_ADVERTISE_V6"); g_adv_v6 = (e && !strcmp(e, "1")) ? 1 : 0; }
    return g_adv_v6;
}
int na_self_advertisable(const char *hostport) {
    if (!hostport || !*hostport) return 0;
    char h[NA_HOST_MAX]; uint16_t p; na_split(hostport, h, sizeof h, &p, 0);
    uint8_t ip[16]; int f = na_to16(h, ip);
    return f == 6 ? na_advertise_v6() : 1;
}
