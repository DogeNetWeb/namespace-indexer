// test_retain.c — raw-block retention (keep the last IDX_RAW_KEEP = 288).
//
// raw_blocks is the reorg-replay substrate. Retention prunes it at the newest
// digest-valid rollback checkpoint <= tip-keep (meta raw_floor); a rollback to
// T >= raw_floor replays from a checkpoint in [raw_floor, T]; T < raw_floor is
// refused with IDX_ROLLBACK_TOO_DEEP and nothing changed. The window is lowered
// through the idx_raw_keep test override so the 48-block fixtures prune.
//   A. prune-then-rollback across the expiry/lapse heights (chain_mkblocks_expiry_br,
//      non-carrier commit expiry + lease lapse) == a fresh, never-pruned sync of the
//      winning branch — names/epochs/muts/commits and state_digest + state_ecmh
//   B. the same on the claim/transfer fixture (chain_mkblocks_rb)
//   C. below the floor: IDX_ROLLBACK_TOO_DEEP, every table byte-identical, RAM state
//      kept; refold refused untouched; a corrupt floor checkpoint FAILS the rollback
//      (never a silent replay from activation over the pruned history)
//   D. mechanics: floor monotonic, checkpoints under it deleted, the floor checkpoint
//      survives the keep-4 prune, no checkpoint => nothing pruned, default 288, the
//      `retain` migration (VACUUM once, raw_retention_v1) is idempotent
//   E. (optional, RETAIN_LIVE_DB=<path>) a COPY of a live db: the migration keeps the
//      state digest; pruned vs unpruned rollbacks at/above the floor are identical;
//      below the floor is refused untouched
#include "sm.h"
#include "db.h"
#include "indexer.h"
#include "oracle_feed.h"
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

int chain_mkblocks_expiry_br(const char *dir, char pfx, int fork, int64_t *times);
int chain_mkblocks_rb(const char *dir, char pfx, int fork, int kind, int nblk);

static int g_fail;
#define CHECK(cond, name) do { \
    if (cond) printf("ok   %s\n", name); \
    else      { printf("FAIL %s\n", name); g_fail = 1; } \
} while (0)
static char g_dir[256];

static int child(const char *log, int argc, char **argv) {   // indexer_main in a child; stdout+stderr -> log
    fflush(stdout); fflush(stderr); pid_t pid = fork();
    if (pid == 0) { int fd = open(log, O_WRONLY|O_CREAT|O_APPEND, 0600); if (fd >= 0) { dup2(fd, 1); dup2(fd, 2); close(fd); }
                    int rc = indexer_main(argc, argv); fflush(NULL); _exit(rc); }
    int st = 0; waitpid(pid, &st, 0); return WIFEXITED(st) ? WEXITSTATUS(st) : 99;
}
static void rm_db(const char *p) {
    char c[2200]; snprintf(c, sizeof c, "rm -f '%s' '%s-wal' '%s-shm' '%s-journal'", p, p, p, p); if (system(c)) {}
}
static int fresh(const char *p, int64_t every) {
    rm_db(p); sqlite3 *db = idx_db_open(p); if (!db) return 0; idx_db_ckpt_set_every(db, every); idx_db_close(db); return 1;
}
// index heights from..to of branch pfx, `step` blocks per projection
static int idx_run(const char *db, char pfx, int from, int to, int step) {
    char lg[400]; snprintf(lg, sizeof lg, "%s/index.log", g_dir);
    for (int a = from; a <= to; a += step) {
        int b = a + step - 1; if (b > to) b = to;
        static char f[64][320]; char *av[80]; int ac = 0;
        av[ac++] = "x"; av[ac++] = "index"; av[ac++] = (char *)db; av[ac++] = "0";
        for (int i = a; i <= b; i++) { snprintf(f[i - a], sizeof f[0], "%s/%c%02d.bin", g_dir, pfx, i); av[ac++] = f[i - a]; }
        av[ac] = NULL;
        if (child(lg, ac, av)) return 0;
    }
    return 1;
}
typedef struct { sqlite3 *db; SmState *s; OracleFeed *o; } Fold;
static int fold_open(Fold *f, const char *p);
static void fold_close(Fold *f);
static int fold_open(Fold *f, const char *p) {
    memset(f, 0, sizeof *f); f->db = idx_db_open(p); if (!f->db) return 0;
    f->s = sm_new((uint64_t)idx_db_get_activation(f->db, 0)); idx_db_load_state(f->db, f->s);
    f->s->cur_height = idx_db_projected_height(f->db);
    f->o = oracle_new(); idx_db_oracle_warm(f->db, f->o);
    oracle_set_subsidy(f->o, idx_db_get_subsidy(f->db, 10000LL * SM_KOINU_PER_DOGE));
    return 1;
}
static void fold_close(Fold *f) { oracle_free(f->o); sm_free(f->s); idx_db_close(f->db); memset(f, 0, sizeof *f); }
// fold pfx 0..to one block per projection on a checkpoints-off db, taking ONE
// checkpoint (idx_db_ckpt_save on the projection, as the seed does) at height ck,
// so with keep = to-ck the retention floor lands exactly on ck
static int run_ck(const char *db, char pfx, int to, int ck) {
    if (!fresh(db, 0) || !idx_run(db, pfx, 0, ck, 1)) return 0;
    Fold f; if (!fold_open(&f, db)) return 0;
    int ok = f.s->cur_height == ck && idx_db_ckpt_save(f.db, f.s); fold_close(&f);
    return ok && idx_run(db, pfx, ck + 1, to, 1);
}
// the live reorg path; returns idx_sync_rollback's code
static int rollback(const char *p, int64_t to) {
    Fold f; if (!fold_open(&f, p)) return -99;
    int rc = idx_sync_rollback(&f.s, f.db, f.o, (int64_t)f.s->activation_height, to);
    if (rc == 1) { uint8_t h[32] = {0}; idx_db_block_get(f.db, to, h); idx_db_save_sync(f.db, to, h); }
    fold_close(&f); return rc;
}
static int64_t q_i64(const char *p, const char *sql) {
    sqlite3 *db = idx_db_open(p); int64_t v = -999; sqlite3_stmt *st;
    if (db && sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) v = sqlite3_column_type(st, 0) == SQLITE_NULL ? -1 : sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    idx_db_close(db); return v;
}
static void q_text(const char *p, const char *sql, char *out, size_t n) {
    sqlite3 *x = idx_db_open(p); sqlite3_stmt *q = NULL; out[0] = 0;
    if (x && sqlite3_prepare_v2(x, sql, -1, &q, NULL) == SQLITE_OK && sqlite3_step(q) == SQLITE_ROW && sqlite3_column_text(q, 0))
        snprintf(out, n, "%s", (const char *)sqlite3_column_text(q, 0));
    sqlite3_finalize(q); idx_db_close(x);
}
// sha256 over EVERY table's rows (all columns, ordered) — the whole db content
static void db_hash(const char *p, uint8_t out[32]) {
    SHA256_CTX c; sha256_init(&c); sqlite3 *db = idx_db_open(p); sqlite3_stmt *t, *st;
    if (db && sqlite3_prepare_v2(db, "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name", -1, &t, NULL) == SQLITE_OK) {
        while (sqlite3_step(t) == SQLITE_ROW) {
            char sql[400]; const char *tn = (const char *)sqlite3_column_text(t, 0);
            sha256_update(&c, (const uint8_t *)tn, (unsigned)strlen(tn));
            snprintf(sql, sizeof sql, "SELECT * FROM \"%s\"", tn);
            if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) continue;
            int nc = sqlite3_column_count(st); sqlite3_finalize(st);
            int o = snprintf(sql, sizeof sql, "SELECT * FROM \"%s\" ORDER BY ", tn);
            for (int i = 1; i <= nc && o < (int)sizeof sql - 8; i++) o += snprintf(sql + o, sizeof sql - (size_t)o, "%s%d", i > 1 ? "," : "", i);
            if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) continue;
            while (sqlite3_step(st) == SQLITE_ROW)
                for (int i = 0; i < nc; i++) {
                    int n = sqlite3_column_bytes(st, i); const void *b = sqlite3_column_blob(st, i);
                    uint8_t tag = (uint8_t)sqlite3_column_type(st, i);
                    sha256_update(&c, &tag, 1); sha256_update(&c, (const uint8_t *)&n, sizeof n);
                    if (b && n) sha256_update(&c, b, (unsigned)n);
                }
            sqlite3_finalize(st);
        }
        sqlite3_finalize(t);
    }
    idx_db_close(db); sha256_final(&c, out);
}
static int digest_out(const char *p, char *out, size_t n) {
    char o[400]; snprintf(o, sizeof o, "%s/dg.out", g_dir); unlink(o);
    char *av[] = { "x", "digest", (char *)p, NULL };
    int ok = child(o, 3, av) == 0;
    FILE *f = fopen(o, "r"); size_t k = f ? fread(out, 1, n - 1, f) : 0; out[k] = 0; if (f) fclose(f);
    return ok && strstr(out, "state_digest");
}
// names / epochs / muts / commits + `digest` equal
static int same(const char *a, const char *b) {
    static const char *Q[] = {
        "SELECT group_concat(x,',') FROM (SELECT name||':'||hex(owner)||':'||lease_expiry||':'||st AS x FROM names ORDER BY name)",
        "SELECT group_concat(name||':'||start_height||':'||coalesce(hex(owner),'-'),',') FROM (SELECT * FROM epochs ORDER BY name,start_height)",
        "SELECT group_concat(hex(owner)||':'||height,',') FROM (SELECT * FROM muts ORDER BY owner)",
        "SELECT group_concat(hex(commitment)||':'||commit_height,',') FROM (SELECT * FROM commits ORDER BY commitment)" };
    char x[8192], y[8192]; int ok = 1;
    for (int i = 0; i < 4; i++) { q_text(a, Q[i], x, sizeof x); q_text(b, Q[i], y, sizeof y); if (strcmp(x, y)) { ok = 0; fprintf(stderr, "  differ q%d:\n   %s\n   %s\n", i, x, y); } }
    if (!digest_out(a, x, sizeof x) || !digest_out(b, y, sizeof y) || strcmp(x, y)) { ok = 0; fprintf(stderr, "  digest differ:\n%s\n%s\n", x, y); }
    return ok;
}

// ── A: expiry/lapse fixture ───────────────────────────────────────────────────
static int g_hc, g_lap;
static void a_case(const char *tag, char pfx, int floor, int fork) {
    char node[400], ref[400], m[300];
    snprintf(node, sizeof node, "%s/A_%c.db", g_dir, pfx); snprintf(ref, sizeof ref, "%s/Aref_%c.db", g_dir, pfx);
    chain_mkblocks_expiry_br(g_dir, pfx, fork, NULL);
    idx_raw_keep = 47 - floor;
    int ok = run_ck(node, 'e', 47, floor);
    int64_t fl = q_i64(node, "SELECT v FROM meta WHERE k='raw_floor'");
    int64_t raw_le = q_i64(node, "SELECT COUNT(*) FROM raw_blocks WHERE height<=(SELECT v FROM meta WHERE k='raw_floor')");
    snprintf(m, sizeof m, "%s: losing branch e00..e47 synced, pruned at floor %d (raw <= floor gone, %lld raw kept)",
             tag, floor, (long long)q_i64(node, "SELECT COUNT(*) FROM raw_blocks"));
    CHECK(ok && fl == floor && raw_le == 0, m);
    int rc = rollback(node, fork);
    snprintf(m, sizeof m, "%s: rollback to %d (>= floor %d) returns 1", tag, fork, floor);
    CHECK(rc == 1, m);
    idx_raw_keep = 0;      // the reference never prunes
    if (fresh(ref, 0) && idx_run(ref, pfx, 0, fork, 48)) {
        snprintf(m, sizeof m, "%s: right after the rollback == fresh never-pruned sync to %d", tag, fork);
        CHECK(same(node, ref), m);
    } else CHECK(0, "reference fold to the fork");
    idx_raw_keep = 47 - floor;
    ok = idx_run(node, pfx, fork + 1, 47, 1);
    idx_raw_keep = 0;
    ok = ok && fresh(ref, 0) && idx_run(ref, pfx, 0, 47, 48);
    snprintf(m, sizeof m, "%s: after connecting the winner %d..47 == fresh never-pruned sync of the winner", tag, fork + 1);
    CHECK(ok && same(node, ref), m);
    rm_db(node); rm_db(ref);
}
static void sec_a(void) {
    printf("\n-- A: prune-then-rollback across commit expiry / lease lapse == fresh sync --\n");
    int64_t t[48]; chain_mkblocks_expiry_br(g_dir, 'e', 99, t);
    int64_t ct = sm_mtp(t + 10, 11); g_hc = -1;
    for (int h = 22; h < 48 && g_hc < 0; h++) { int lo = h > 11 ? h - 11 : 0; if (sm_mtp(t + lo, h - lo) > ct + 18000) g_hc = h; }
    char probe[400], v[64]; snprintf(probe, sizeof probe, "%s/probe.db", g_dir);
    idx_raw_keep = 0; fresh(probe, 0); idx_run(probe, 'e', 0, 47, 48);
    q_text(probe, "SELECT start_height FROM epochs WHERE name='alice' AND owner IS NULL", v, sizeof v); g_lap = atoi(v);
    rm_db(probe);
    printf("  info: carriers 0,1,6,21; carol's commit expires at %d, alice lapses at %d\n", g_hc, g_lap);
    CHECK(g_hc > 21 && g_lap > g_hc && g_lap < 46, "fixture: non-carrier expiry, then non-carrier lapse, after the last carrier");
    a_case("carrier kept (floor 10 < carrier 21, fork 45 spans expiry+lapse)", 'p', 10, 45);
    a_case("carrier kept (floor 10), fork 23: carol's commit at 21 still live, replayed from raw", 'x', 10, 23);
    a_case("all carriers pruned (floor 22, fork 45 spans expiry+lapse)", 'q', 22, 45);
    a_case("floor below the expiry, fork AT the expiry", 'r', g_hc - 1, g_hc);
    a_case("rollback exactly TO the floor at the expiry height", 's', g_hc, g_hc);
    a_case("floor between expiry and lapse, fork AT the lapse", 't', g_lap - 1, g_lap);
    a_case("rollback exactly TO the floor at the lapse height", 'u', g_lap, g_lap);
    a_case("shallow (floor 39, fork 40)", 'w', 39, 40);
}

// ── B: claim/transfer fixture ─────────────────────────────────────────────────
#define NB 40
static void sec_b(void) {
    printf("\n-- B: prune-then-rollback with claims/transfers (rb fixture) == fresh sync --\n");
    if (chain_mkblocks_rb(g_dir, 'a', NB, 2, NB) || chain_mkblocks_rb(g_dir, 'd', 15, 1, NB) || chain_mkblocks_rb(g_dir, 'c', 15, 0, NB)) {
        CHECK(0, "rb fixture"); return;
    }
    const struct { char pfx; int floor, fork; const char *tag; } C[] = {
        { 'd', 9, 15, "floor 9 (claims at 1/5 pruned), fork 15: transfer at 22 CHANGED" },
        { 'c', 9, 15, "floor 9, fork 15: transfer at 22 REMOVED" },
        { 'c', 13, 15, "floor 13 (above alice's transfer at 12), fork 15" },
    };
    for (unsigned i = 0; i < sizeof C / sizeof C[0]; i++) {
        char node[400], ref[400], m[300];
        snprintf(node, sizeof node, "%s/B.db", g_dir); snprintf(ref, sizeof ref, "%s/Bref.db", g_dir);
        idx_raw_keep = NB - 1 - C[i].floor;
        int ok = run_ck(node, 'a', NB - 1, C[i].floor)
              && q_i64(node, "SELECT v FROM meta WHERE k='raw_floor'") == C[i].floor
              && q_i64(node, "SELECT COUNT(*) FROM raw_blocks WHERE height<=(SELECT v FROM meta WHERE k='raw_floor')") == 0;
        ok = ok && rollback(node, C[i].fork) == 1 && idx_run(node, C[i].pfx, C[i].fork + 1, NB - 1, 1);
        idx_raw_keep = 0;
        ok = ok && fresh(ref, 0) && idx_run(ref, C[i].pfx, 0, NB - 1, NB);
        snprintf(m, sizeof m, "%s == fresh sync of %c", C[i].tag, C[i].pfx);
        CHECK(ok && same(node, ref), m);
        rm_db(node); rm_db(ref);
    }
}

// ── C: below the floor ────────────────────────────────────────────────────────
static void sec_c(void) {
    printf("\n-- C: below the floor: refused, nothing changed --\n");
    char node[400], cp[900], m[300]; snprintf(node, sizeof node, "%s/C.db", g_dir);
    idx_raw_keep = 17;                                 // floor 30 at tip 47
    if (!run_ck(node, 'e', 47, 30)) { CHECK(0, "C fold"); return; }
    CHECK(q_i64(node, "SELECT v FROM meta WHERE k='raw_floor'") == 30, "floor 30 at tip 47 (keep 17)");
    uint8_t h0[32], h1[32]; db_hash(node, h0);
    int64_t tos[] = { 29, 21, 3, 0, -1 }; int all = 1;
    for (int i = 0; i < 5; i++) {
        Fold f; fold_open(&f, node); uint8_t d0[32], d1[32]; sm_state_digest(f.s, d0);
        SmState *before = f.s;
        int rc = idx_sync_rollback(&f.s, f.db, f.o, (int64_t)f.s->activation_height, tos[i]);
        sm_state_digest(f.s, d1);
        int ram = f.s == before && !memcmp(d0, d1, 32) && f.s->cur_height == 47;
        fold_close(&f); db_hash(node, h1);
        if (!(rc == IDX_ROLLBACK_TOO_DEEP && ram && !memcmp(h0, h1, 32))) { all = 0; printf("     to %lld: rc %d ram %d\n", (long long)tos[i], rc, ram); }
    }
    CHECK(all, "rollback to 29 / 21 / 3 / 0 / -1 (below floor 30): IDX_ROLLBACK_TOO_DEEP, every table byte-identical, RAM state untouched");
    CHECK(rollback(node, 30) == 1, "rollback exactly to the floor (30) is allowed");
    // refold: refused before it wipes anything
    db_hash(node, h0);
    { char lg[400]; snprintf(lg, sizeof lg, "%s/refold.log", g_dir); unlink(lg);
      char *av[] = { "x", "refold", node, NULL }; int rc = child(lg, 3, av); db_hash(node, h1);
      CHECK(rc != 0 && !memcmp(h0, h1, 32), "refold on a pruned db is refused, db byte-identical"); }
    // a corrupt floor checkpoint: the rollback FAILS (no silent replay from activation)
    snprintf(cp, sizeof cp, "cp '%s' '%s.bad'", node, node); char bad[500]; snprintf(bad, sizeof bad, "%s.bad", node);
    if (system(cp) == 0) {
        sqlite3 *db = idx_db_open(bad); sqlite3_exec(db, "UPDATE rb_ckpt SET digest=zeroblob(32) WHERE height=30", NULL, NULL, NULL); idx_db_close(db);
        db_hash(bad, h0); int rc = rollback(bad, 30); db_hash(bad, h1);
        snprintf(m, sizeof m, "corrupt floor checkpoint: rollback to the floor returns 0 (rc %d), db byte-identical", rc);
        CHECK(rc == 0 && !memcmp(h0, h1, 32), m);
        rm_db(bad);
    }
    rm_db(node);
}

// ── D: mechanics ──────────────────────────────────────────────────────────────
static void sec_d(void) {
    printf("\n-- D: floor / checkpoint mechanics, migration --\n");
    CHECK(IDX_RAW_KEEP == 288, "production window IDX_RAW_KEEP == 288");
    char node[400], m[300]; snprintf(node, sizeof node, "%s/D.db", g_dir);
    // checkpoints every 5, projections every 5, keep 12
    idx_raw_keep = 12;
    int ok = fresh(node, 5) && idx_run(node, 'e', 0, 47, 5);
    int64_t fl = q_i64(node, "SELECT v FROM meta WHERE k='raw_floor'");
    snprintf(m, sizeof m, "every=5: floor = newest checkpoint <= tip-12 (tip 47 -> %lld)", (long long)fl);
    CHECK(ok && fl == q_i64(node, "SELECT MAX(height) FROM rb_ckpt WHERE height<=35") && fl > 0 && fl <= 35, m);
    CHECK(q_i64(node, "SELECT COUNT(*) FROM rb_ckpt WHERE height<(SELECT v FROM meta WHERE k='raw_floor')") == 0
          && q_i64(node, "SELECT COUNT(*) FROM rb_ckpt WHERE height=(SELECT v FROM meta WHERE k='raw_floor')") == 1,
          "checkpoints under the floor deleted; the floor checkpoint kept");
    rm_db(node);
    // automatic checkpoints every 7, projection per block, keep 20 (<= 3*7: the keep-4
    // rotation always holds a checkpoint <= tip-20): floor = newest multiple of 7 <= tip-20
    idx_raw_keep = 20; ok = fresh(node, 7);
    int mono = 1; int64_t last = -999;
    for (int h = 0; ok && h <= 47; h++) {
        ok = idx_run(node, 'e', h, h, 1);
        int64_t f = q_i64(node, "SELECT v FROM meta WHERE k='raw_floor'");
        int64_t want = (h - 20) >= 7 ? ((h - 20) / 7) * 7 : -999;
        if (f < last || f != want) { mono = 0; printf("     h %d floor %lld want %lld\n", h, (long long)f, (long long)want); }
        last = f;
    }
    CHECK(ok && mono, "every=7, keep 20: floor == newest checkpoint <= tip-20 at every height (none until 27), never moves down");
    CHECK(q_i64(node, "SELECT COUNT(*) FROM rb_ckpt") <= 4 && q_i64(node, "SELECT MIN(height) FROM rb_ckpt") == 21,
          "checkpoint rows stay bounded (keep-4), the oldest is the floor (21)");
    // a rollback (to >= floor) does not move the floor down, re-sync moves it up again
    ok = rollback(node, 30) == 1 && q_i64(node, "SELECT v FROM meta WHERE k='raw_floor'") == 21 && idx_run(node, 'e', 31, 47, 1)
         && q_i64(node, "SELECT v FROM meta WHERE k='raw_floor'") == 21 && rollback(node, 20) == IDX_ROLLBACK_TOO_DEEP;
    CHECK(ok, "rollback to 30 keeps floor 21; reconnecting 31..47 keeps 21; rollback to 20 refused");
    rm_db(node);
    // no checkpoints => nothing pruned
    idx_raw_keep = 5; ok = fresh(node, 0) && idx_run(node, 'e', 0, 47, 1);
    CHECK(ok && q_i64(node, "SELECT COUNT(*) FROM raw_blocks") == 4 && q_i64(node, "SELECT COUNT(*) FROM meta WHERE k='raw_floor'") == 0,
          "checkpoints off: no floor, all 4 raw carrier blocks kept");
    rm_db(node);
    // the `retain` migration on an unpruned db (as an upgraded live db): prune + VACUUM once, digest unchanged, idempotent
    idx_raw_keep = 0; ok = fresh(node, 10) && idx_run(node, 'e', 0, 47, 10);
    char d0[2048], d1[2048], lg[400]; snprintf(lg, sizeof lg, "%s/retain.log", g_dir); unlink(lg);
    ok = ok && digest_out(node, d0, sizeof d0) && q_i64(node, "SELECT COUNT(*) FROM raw_blocks") == 4
            && q_i64(node, "SELECT COUNT(*) FROM meta WHERE k='raw_floor'") == 0;
    idx_raw_keep = 10;
    char *av[] = { "x", "retain", node, NULL };
    int rc1 = child(lg, 3, av);
    int64_t f1 = q_i64(node, "SELECT v FROM meta WHERE k='raw_floor'");
    ok = ok && rc1 == 0 && digest_out(node, d1, sizeof d1) && !strcmp(d0, d1)
            && q_i64(node, "SELECT v FROM meta WHERE k='raw_retention_v1'") == 1 && f1 == 29
            && q_i64(node, "SELECT COUNT(*) FROM raw_blocks") == 0;
    CHECK(ok, "retain <db>: floor 29 (newest ckpt <= 47-10; ckpts 19/29/39), raw <= floor pruned, VACUUM + raw_retention_v1, digest unchanged");
    uint8_t h0[32], h1[32]; db_hash(node, h0); int rc2 = child(lg, 3, av); db_hash(node, h1);
    CHECK(rc2 == 0 && !memcmp(h0, h1, 32), "retain is idempotent (second run changes nothing)");
    { FILE *f = fopen(lg, "r"); char b[8192]; size_t n = f ? fread(b, 1, sizeof b - 1, f) : 0; b[n] = 0; if (f) fclose(f);
      CHECK(strstr(b, "VACUUM done") && strstr(b, "VACUUM done") == strstr(b, "VACUUM") && !strstr(strstr(b, "VACUUM done") + 1, "VACUUM done"),
            "VACUUM runs exactly once"); }
    rm_db(node);
}

// ── E: a copy of a live db ────────────────────────────────────────────────────
static void sec_e(const char *live) {
    printf("\n-- E: live db copy (%s) --\n", live);
    idx_raw_keep = IDX_RAW_KEEP;
    char full[400], pr[400], a[500], b[500], c[2200], m[300], d0[2048], d1[2048];
    snprintf(full, sizeof full, "%s/live_full.db", g_dir); snprintf(pr, sizeof pr, "%s/live_pruned.db", g_dir);
    snprintf(c, sizeof c, "cp '%s' '%s' && cp '%s' '%s'", live, full, live, pr);
    if (system(c) != 0) { CHECK(0, "copy live db"); return; }
    int64_t tip = q_i64(full, "SELECT v FROM meta WHERE k='proj_height'");
    int64_t raw0 = q_i64(full, "SELECT COUNT(*) FROM raw_blocks");
    char lg[400]; snprintf(lg, sizeof lg, "%s/live_retain.log", g_dir); unlink(lg);
    char *av[] = { "x", "retain", pr, NULL };
    int ok = digest_out(full, d0, sizeof d0) && child(lg, 3, av) == 0 && digest_out(pr, d1, sizeof d1) && !strcmp(d0, d1);
    int64_t fl = q_i64(pr, "SELECT v FROM meta WHERE k='raw_floor'");
    snprintf(m, sizeof m, "migration: tip %lld, floor %lld (<= tip-288), raw %lld -> %lld, raw_retention_v1, digest unchanged",
             (long long)tip, (long long)fl, (long long)raw0, (long long)q_i64(pr, "SELECT COUNT(*) FROM raw_blocks"));
    CHECK(ok && fl >= 0 && fl <= tip - 288 && q_i64(pr, "SELECT v FROM meta WHERE k='raw_retention_v1'") == 1
          && q_i64(pr, "SELECT COUNT(*) FROM raw_blocks WHERE height<=(SELECT v FROM meta WHERE k='raw_floor')") == 0, m);
    { char ic[64]; q_text(pr, "PRAGMA integrity_check", ic, sizeof ic); CHECK(!strcmp(ic, "ok"), "pruned live copy: integrity_check ok"); }
    int64_t tos[] = { tip - 1, tip - 100, tip - 288, fl + 1, fl };
    for (int i = 0; i < 5; i++) {
        snprintf(a, sizeof a, "%s.x", full); snprintf(b, sizeof b, "%s.x", pr);
        snprintf(c, sizeof c, "cp '%s' '%s' && cp '%s' '%s'", full, a, pr, b);
        if (system(c) != 0) { CHECK(0, "copy"); continue; }
        int ra = rollback(a, tos[i]), rb = rollback(b, tos[i]);
        snprintf(m, sizeof m, "rollback to %lld (tip-%lld): pruned == unpruned (state rows + digest)", (long long)tos[i], (long long)(tip - tos[i]));
        CHECK(ra == 1 && rb == 1 && same(a, b), m);
        rm_db(a); rm_db(b);
    }
    uint8_t h0[32], h1[32]; db_hash(pr, h0);
    int rc = rollback(pr, fl - 1); db_hash(pr, h1);
    snprintf(m, sizeof m, "rollback to floor-1 (%lld): IDX_ROLLBACK_TOO_DEEP, live copy byte-identical", (long long)(fl - 1));
    CHECK(rc == IDX_ROLLBACK_TOO_DEEP && !memcmp(h0, h1, 32), m);
    rm_db(full); rm_db(pr);
}

int main(void) {
    snprintf(g_dir, sizeof g_dir, "/tmp/test_retain.XXXXXX");
    if (!mkdtemp(g_dir)) { perror("mkdtemp"); return 2; }
    sec_a(); sec_b(); sec_c(); sec_d();
    const char *live = getenv("RETAIN_LIVE_DB");
    if (live && *live) sec_e(live);
    char c[400]; snprintf(c, sizeof c, "rm -rf '%s'", g_dir); if (system(c)) {}
    printf("\ntest_retain: %s\n", g_fail ? "FAILED" : "ALL PASSED");
    return g_fail;
}
