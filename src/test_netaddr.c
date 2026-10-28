// test_netaddr.c — IPv4/IPv6 address helpers + dual-stack listen (no sqlite, no P2P).
#include "netaddr.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int g_fail;
#define CK(c, m) do { if (c) printf("  ok   %s\n", m); \
                      else { printf("  FAIL %s\n", m); g_fail++; } } while (0)

int main(void) {
    // ── IPv6 dual-stack: parse/format ──
    {
        char h[NA_HOST_MAX], o[80]; uint16_t p;
        na_split("1.2.3.4:33874", h, sizeof h, &p, 9); CK(!strcmp(h, "1.2.3.4") && p == 33874, "split v4:port");
        na_split("1.2.3.4", h, sizeof h, &p, 9);       CK(!strcmp(h, "1.2.3.4") && p == 9, "split v4 default port");
        na_split("[2a01:4f8::1]:33874", h, sizeof h, &p, 9); CK(!strcmp(h, "2a01:4f8::1") && p == 33874, "split [v6]:port");
        na_split("[2a01:4f8::1]", h, sizeof h, &p, 9);  CK(!strcmp(h, "2a01:4f8::1") && p == 9, "split [v6]");
        na_split("2a01:4f8::1", h, sizeof h, &p, 9);    CK(!strcmp(h, "2a01:4f8::1") && p == 9, "split bare v6 keeps all");
        na_split("seed.dogecoin.surf:33874", h, sizeof h, &p, 9); CK(!strcmp(h, "seed.dogecoin.surf") && p == 33874, "split host:port");
        na_join(o, sizeof o, "2a01:4f8::1", 33874); CK(!strcmp(o, "[2a01:4f8::1]:33874"), "join v6 bracketed");
        na_join(o, sizeof o, "1.2.3.4", 33874);     CK(!strcmp(o, "1.2.3.4:33874"), "join v4 unchanged");
    }
    // ── mapped round-trips ──
    {
        uint8_t ip[16]; char h[NA_HOST_MAX];
        CK(na_to16("1.2.3.4", ip) == 4 && ip[10] == 0xFF && ip[11] == 0xFF && ip[12] == 1 && ip[15] == 4, "v4 → ::ffff:1.2.3.4 bytes");
        CK(na_from16(ip, h, sizeof h) == 4 && !strcmp(h, "1.2.3.4"), "mapped bytes → dotted");
        CK(na_to16("::ffff:1.2.3.4", ip) == 4 && na_from16(ip, h, sizeof h) == 4 && !strcmp(h, "1.2.3.4"), "::ffff:1.2.3.4 text → dotted");
        CK(na_canon("::FFFF:5.6.7.8", h, sizeof h) == 4 && !strcmp(h, "5.6.7.8"), "canon mapped");
        CK(na_canon("2A01:04F8:0000::0001", h, sizeof h) == 6 && !strcmp(h, "2a01:4f8::1"), "canon v6 compress/lower");
        CK(na_to16("2a01:4f8::1", ip) == 6 && na_from16(ip, h, sizeof h) == 6 && !strcmp(h, "2a01:4f8::1"), "v6 round-trip");
        CK(!na_to16("example.com", ip) && !na_to16("[::1]", ip), "non-numeric rejected");
        struct sockaddr_in6 s6; memset(&s6, 0, sizeof s6); s6.sin6_family = AF_INET6; s6.sin6_port = htons(4242);
        inet_pton(AF_INET6, "::ffff:9.8.7.6", &s6.sin6_addr); unsigned pt = 0;
        CK(na_sockaddr((struct sockaddr *)&s6, h, sizeof h, &pt) == 4 && !strcmp(h, "9.8.7.6") && pt == 4242, "accepted mapped sockaddr → v4 text");
    }
    // ── policy ──
    {
        struct { const char *a; int r; } pc[] = {
            {"8.8.8.8",1},{"10.1.2.3",0},{"127.0.0.1",0},{"192.168.1.1",0},{"172.20.0.1",0},{"169.254.1.1",0},{"0.0.0.0",0},{"224.0.0.1",0},
            {"::ffff:8.8.8.8",1},{"::ffff:10.0.0.1",0},
            {"2a01:4f8:c0c:1::2",1},{"2600:1f18::1",1},{"2001:470::1",1},
            {"::",0},{"::1",0},{"fd00::1",0},{"fc12::1",0},{"fe80::1",0},{"fec0::1",0},{"ff02::1",0},
            {"2001:db8::1",0},{"2001:0:4136:e378::1",0},{"2002:c000:204::1",0},{"64:ff9b::808:808",0},
            {"100::1",0},{"::8.8.8.8",0},{"2001:10::1",0},{"3fff::1",0},{"4000::1",0},
        };
        for (size_t i = 0; i < sizeof pc / sizeof pc[0]; i++) {
            char m[96]; snprintf(m, sizeof m, "routable(%s) == %d", pc[i].a, pc[i].r);
            CK(na_routable(pc[i].a) == pc[i].r, m);
        }
        char g1[40], g2[40];
        na_group("2a01:4f8:1::1", g1, sizeof g1); na_group("2a01:4f8:ffff::9", g2, sizeof g2);
        CK(!strcmp(g1, g2) && !strcmp(g1, "v6:2a01:04f8"), "v6 netgroup is /32");
        na_group("2a01:4f9::1", g2, sizeof g2); CK(strcmp(g1, g2), "different /32 differs");
        na_group("1.2.3.4", g1, sizeof g1); CK(!strcmp(g1, "1.2"), "v4 netgroup /16 unchanged");
    }
    // ── listen: dual-stack, v4 + v6 loopback connect, forced v4 fallback ──
    {
        uint16_t port = (uint16_t)(getenv("NA_TEST_PORT") ? atoi(getenv("NA_TEST_PORT")) : 18733);
        int fam = 0, lfd = na_listen_any(port, 4, 1, &fam);
        CK(lfd >= 0 && fam == 6, "dual-stack listen on [::]");
        const char *tgt[2] = { "::1", "127.0.0.1" }; const char *want[2] = { "::1", "127.0.0.1" };
        for (int k = 0; k < 2 && lfd >= 0; k++) {
            struct sockaddr_storage ss; socklen_t sl; memset(&ss, 0, sizeof ss);
            if (k == 0) { struct sockaddr_in6 *a = (void *)&ss; a->sin6_family = AF_INET6; a->sin6_port = htons(port); inet_pton(AF_INET6, tgt[k], &a->sin6_addr); sl = sizeof *a; }
            else        { struct sockaddr_in  *a = (void *)&ss; a->sin_family = AF_INET;  a->sin_port = htons(port);  inet_pton(AF_INET, tgt[k], &a->sin_addr);   sl = sizeof *a; }
            int c = socket(ss.ss_family, SOCK_STREAM, 0);
            int ok = c >= 0 && connect(c, (struct sockaddr *)&ss, sl) == 0;
            struct sockaddr_storage pa; socklen_t pl = sizeof pa; int a = ok ? accept(lfd, (struct sockaddr *)&pa, &pl) : -1;
            char h[NA_HOST_MAX] = "", m[80]; unsigned rp = 0;
            if (a >= 0) na_sockaddr((struct sockaddr *)&pa, h, sizeof h, &rp);
            snprintf(m, sizeof m, "connect %s → accepted peer text %s", tgt[k], h);
            CK(a >= 0 && !strcmp(h, want[k]) && rp, m);
            if (a >= 0) close(a);
            if (c >= 0) close(c);
        }
        int busy = na_listen_any(port, 4, 1, &fam);
        CK(busy < 0 && errno == EADDRINUSE, "port in use reported as EADDRINUSE (dial-only path)");
        if (lfd >= 0) close(lfd);
        int v4 = na_listen_any(port, 4, 0, &fam);
        CK(v4 >= 0 && fam == 4, "allow_v6=0 → IPv4-only listener");
        if (v4 >= 0) close(v4);
        setenv("IDX_IPV6", "0", 1); CK(!na_ipv6_allowed(), "IDX_IPV6=0 disables v6"); unsetenv("IDX_IPV6");
        CK(na_ipv6_allowed(), "v6 allowed by default");
    }

    if (g_fail) { printf("test_netaddr: %d FAIL\n", g_fail); return 1; }
    printf("test_netaddr: ALL PASSED\n");
    return 0;
}
