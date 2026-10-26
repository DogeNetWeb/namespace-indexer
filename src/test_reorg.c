// test_reorg — reorg rollback must equal a fresh sync of the winning branch
// (port of PepeNet idx-13). A node syncs branch 'e' (48 blocks with a
// non-carrier commit expiry and a non-carrier lease lapse after the last
// carrier), rolls back to the fork point with idx_sync_rollback — exactly what
// the live reorg path does — then connects the winning branch. Its db must
// match a fresh sync of the winner: names, epochs, muts, commits, and the
// `digest` output (state_digest + state_ecmh). Four forks: crossing the
// expiry+lapse, at the expiry, at the lapse, deep.
#include "indexer.h"
#include "db.h"
#include "oracle_feed.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

int chain_mkblocks_expiry_br(const char *dir, char pfx, int fork, int64_t *times);

static int g_fail;
#define CHECK(cond, name) do { \
    if (cond) printf("ok   %s\n", name); \
    else      { printf("FAIL %s\n", name); g_fail = 1; } \
} while (0)

static int child_to(const char *out, int argc, char **argv) {   // indexer_main in a child, stdout -> out
    fflush(stdout); pid_t pid = fork();
    if (pid == 0) { int fd = open(out, O_WRONLY|O_CREAT|O_TRUNC, 0600); if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); close(fd); }
                    int rc = indexer_main(argc, argv); fflush(NULL); _exit(rc); }
    int st = 0; waitpid(pid, &st, 0); return WIFEXITED(st) ? WEXITSTATUS(st) : 99;
}
static int r_index(const char *db, const char *dir, char pfx, int from, int to) {
    static char f[48][320]; char *av[64]; int ac = 0; char lg[400];
    av[ac++] = "x"; av[ac++] = "index"; av[ac++] = (char *)db; av[ac++] = "0";
    for (int i = from; i <= to; i++) { snprintf(f[i], sizeof f[i], "%s/%c%02d.bin", dir, pfx, i); av[ac++] = f[i]; }
    av[ac] = NULL; snprintf(lg, sizeof lg, "%s/index.log", dir);
    return child_to(lg, ac, av);
}
// the live reorg path: idx_sync_rollback to the fork point, sync tip = fork
static int r_rollback(const char *dbp, int64_t fork_h) {
    sqlite3 *db = idx_db_open(dbp); if (!db) return 0;
    SmState *s = sm_new((uint64_t)idx_db_get_activation(db, 0));
    idx_db_load_state(db, s);
    OracleFeed *o = oracle_new(); idx_db_oracle_warm(db, o);
    oracle_set_subsidy(o, idx_db_get_subsidy(db, 10000LL * SM_KOINU_PER_DOGE));
    int ok = idx_sync_rollback(&s, db, o, (int64_t)s->activation_height, fork_h) != 0;
    uint8_t h[32] = {0}; ok = ok && idx_db_block_get(db, fork_h, h);
    if (ok) idx_db_save_sync(db, fork_h, h);
    oracle_free(o); sm_free(s); idx_db_close(db); return ok;
}
static void r_q(const char *p, const char *sql, char *out, size_t n) {
    sqlite3 *x = NULL; sqlite3_stmt *q = NULL; out[0] = 0;
    if (sqlite3_open(p, &x) == SQLITE_OK && sqlite3_prepare_v2(x, sql, -1, &q, NULL) == SQLITE_OK &&
        sqlite3_step(q) == SQLITE_ROW && sqlite3_column_text(q, 0)) snprintf(out, n, "%s", (const char *)sqlite3_column_text(q, 0));
    sqlite3_finalize(q); sqlite3_close(x);
}
static void slurp(const char *p, char *out, size_t n) {
    FILE *f = fopen(p, "r"); size_t k = f ? fread(out, 1, n - 1, f) : 0; out[k] = 0; if (f) fclose(f);
}
static void r_same(const char *tag, const char *dir, const char *a, const char *b) {
    static const char *Q[] = {
        "SELECT group_concat(x,',') FROM (SELECT name||':'||hex(owner)||':'||lease_expiry AS x FROM names ORDER BY name)",
        "SELECT group_concat(name||':'||start_height||':'||coalesce(hex(owner),'-'),',') FROM (SELECT * FROM epochs ORDER BY name,start_height)",
        "SELECT group_concat(hex(owner)||':'||height,',') FROM (SELECT * FROM muts ORDER BY owner)",
        "SELECT count(*) FROM commits" };
    static const char *L[] = { "names", "epochs", "muts", "commits" };
    char m[240], x[4096], y[4096];
    for (int i = 0; i < 4; i++) { r_q(a, Q[i], x, sizeof x); r_q(b, Q[i], y, sizeof y);
        snprintf(m, sizeof m, "%s: %s equal to a fresh sync of the winning branch", tag, L[i]); CHECK(!strcmp(x, y), m); }
    char oa[400], ob[400]; snprintf(oa, sizeof oa, "%s/dg_a", dir); snprintf(ob, sizeof ob, "%s/dg_b", dir);
    char *va[] = { "x", "digest", (char *)a, NULL }, *vb[] = { "x", "digest", (char *)b, NULL };
    int ok = child_to(oa, 3, va) == 0 && child_to(ob, 3, vb) == 0;
    slurp(oa, x, sizeof x); slurp(ob, y, sizeof y);
    snprintf(m, sizeof m, "%s: digest (state_digest, state_ecmh) equal", tag);
    CHECK(ok && strstr(x, "state_digest") && !strcmp(x, y), m);
    if (!(ok && strstr(x, "state_digest") && !strcmp(x, y))) fprintf(stderr, "  ok=%d\n  rolled-back: %s\n  fresh:       %s\n", ok, x, y);
}
static void r_case(const char *dir, const char *tag, char pfx, int fork_h, int check_at_fork) {
    char node[400], fresh[400], c[1000], m[240];
    snprintf(node, sizeof node, "%s/n_%c.db", dir, pfx); snprintf(fresh, sizeof fresh, "%s/f_%c.db", dir, pfx);
    snprintf(c, sizeof c, "rm -f '%s'* '%s'*", node, fresh); if (system(c)) {}
    chain_mkblocks_expiry_br(dir, pfx, fork_h, NULL);
    snprintf(m, sizeof m, "%s: node synced losing branch e00..e47, rolled back to %d", tag, fork_h);
    CHECK(r_index(node, dir, 'e', 0, 47) == 0 && r_rollback(node, fork_h), m);
    if (check_at_fork) {
        CHECK(r_index(fresh, dir, pfx, 0, fork_h) == 0, "fresh sync to the fork point");
        char t2[160]; snprintf(t2, sizeof t2, "%s (right after rollback)", tag); r_same(t2, dir, node, fresh);
    }
    snprintf(m, sizeof m, "%s: node connects winning branch %d..47", tag, fork_h + 1);
    CHECK(r_index(node, dir, pfx, fork_h + 1, 47) == 0, m);
    snprintf(c, sizeof c, "rm -f '%s'*", fresh); if (system(c)) {}
    CHECK(r_index(fresh, dir, pfx, 0, 47) == 0, "fresh sync of the winning branch");
    r_same(tag, dir, node, fresh);
}
int main(void) {
    char dir[] = "/tmp/test_reorg.XXXXXX"; if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    int64_t t[48]; chain_mkblocks_expiry_br(dir, 'e', 99, t);
    // carol commits at 21; spec expiry = first height whose MTP > commit MTP + 18000
    int64_t ct = sm_mtp(t + 10, 11); int hc = -1;
    for (int h = 22; h < 48 && hc < 0; h++) { int lo = h > 11 ? h - 11 : 0; if (sm_mtp(t + lo, h - lo) > ct + 18000) hc = h; }
    char lv[400], v[64]; snprintf(lv, sizeof lv, "%s/probe.db", dir); r_index(lv, dir, 'e', 0, 47);
    r_q(lv, "SELECT start_height FROM epochs WHERE name='alice' AND owner IS NULL", v, sizeof v);
    int lap = atoi(v);
    printf("  info: carol's commit expires at %d, alice lapses at %d (carriers 0,1,6,21)\n", hc, lap);
    CHECK(hc > 21 && hc < lap && lap > 21, "fixture has a non-carrier expiry, then a non-carrier lapse, after the last carrier");
    r_case(dir, "crossing (fork 40, rollback range spans expiry+lapse)", 'a', 40, 1);
    r_case(dir, "exact expiry (fork at carol's expiry height)", 'c', hc, 1);
    r_case(dir, "exact lapse (fork at alice's lapse height)", 'l', lap, 1);
    r_case(dir, "deep (fork 3, 44 blocks replaced)", 'd', 3, 0);
    char c[600]; snprintf(c, sizeof c, "rm -rf '%s'", dir); if (system(c)) {}
    printf(g_fail ? "test_reorg: FAILED\n" : "test_reorg: ALL PASSED\n");
    return g_fail;
}
