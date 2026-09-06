/* hf_winfuzz.c -- a minimal coverage-guided fuzzer for hosts WITHOUT the libFuzzer runtime.
 *
 * Windows-on-ARM ships clang but no clang_rt.fuzzer.lib, so a libFuzzer harness cannot link
 * there. The instrumentation (-fsanitize-coverage=trace-pc-guard) works; only the engine is
 * missing. This IS that engine: edge feedback via the trace-pc-guard callbacks, a corpus that
 * keeps any input hitting a new edge, byte + dictionary mutation, and SEH to catch the crash.
 * It drives the SAME LLVMFuzzerTestOneInput a libFuzzer harness defines, so one harness runs
 * on every host -- libFuzzer where the runtime exists, this where it does not. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* ---- edge coverage (trace-pc-guard) ---- */
#define HF_MAXG (1u << 22)
static uint8_t  hf_seen[HF_MAXG];
static uint32_t hf_edges = 0;

/* trace-pc: called on every edge with no guard array and no sections (which Windows COFF
 * does not give __start_/__stop_ boundary symbols for). The caller's return address is a
 * stable per-edge id; hash it into the bitmap. Collisions only under-count, never crash. */
void __sanitizer_cov_trace_pc(void) {
    uintptr_t pc = (uintptr_t)__builtin_return_address(0);
    uint32_t i = (uint32_t)((pc ^ (pc >> 15) ^ (pc >> 29)) & (HF_MAXG - 1));
    if (!hf_seen[i]) { hf_seen[i] = 1; hf_edges++; }
}
/* also satisfy trace-cmp hooks if enabled (no-ops keep the link clean) */
void __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b) { (void)a;(void)b; }
void __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b) { (void)a;(void)b; }
void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b) { (void)a;(void)b; }
void __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b) { (void)a;(void)b; }

/* ---- corpus ---- */
typedef struct { uint8_t *b; size_t n; } Unit;
static Unit  *corp = NULL;
static size_t corp_n = 0, corp_cap = 0;
static void corp_add(const uint8_t *b, size_t n) {
    if (corp_n == corp_cap) { corp_cap = corp_cap ? corp_cap * 2 : 256;
        corp = (Unit *)realloc(corp, corp_cap * sizeof(Unit)); }
    corp[corp_n].b = (uint8_t *)malloc(n ? n : 1);
    memcpy(corp[corp_n].b, b, n); corp[corp_n].n = n; corp_n++;
}

/* ---- dictionary (libFuzzer .dict subset: name="value" with \xHH, \\, \") ---- */
static uint8_t **dict = NULL; static size_t *dict_len = NULL; static size_t dict_n = 0;
static void dict_add(const uint8_t *b, size_t n) {
    dict = (uint8_t **)realloc(dict, (dict_n + 1) * sizeof(uint8_t *));
    dict_len = (size_t *)realloc(dict_len, (dict_n + 1) * sizeof(size_t));
    dict[dict_n] = (uint8_t *)malloc(n ? n : 1); memcpy(dict[dict_n], b, n);
    dict_len[dict_n] = n; dict_n++;
}
static void dict_load(const char *path) {
    FILE *f = fopen(path, "rb"); if (!f) return; char line[4096];
    while (fgets(line, sizeof line, f)) {
        char *q = strchr(line, '"'); if (!q) continue; q++;
        uint8_t val[2048]; size_t vn = 0;
        while (*q && *q != '"' && vn < sizeof val) {
            if (*q == '\\') { q++;
                if (*q == 'x') { int hi, lo; q++; hi = *q++; lo = *q;
                    char h[3] = { (char)hi, (char)lo, 0 }; val[vn++] = (uint8_t)strtol(h, 0, 16); q++; }
                else if (*q == 'n') { val[vn++] = 10; q++; }
                else if (*q == 'r') { val[vn++] = 13; q++; }
                else if (*q == 't') { val[vn++] = 9; q++; }
                else { val[vn++] = (uint8_t)*q++; }
            } else val[vn++] = (uint8_t)*q++;
        }
        if (vn) dict_add(val, vn);
    }
    fclose(f);
}

/* ---- rng + mutation ---- */
static uint64_t hf_rng = 0x9e3779b97f4a7c15ULL;
static uint64_t rnd(void) { hf_rng ^= hf_rng << 13; hf_rng ^= hf_rng >> 7; hf_rng ^= hf_rng << 17; return hf_rng; }
static size_t mutate(const uint8_t *in, size_t n, uint8_t *out, size_t cap) {
    size_t m = n; if (m > cap) m = cap; if (m) memcpy(out, in, m);
    int rounds = 1 + (int)(rnd() % 5);
    for (int r = 0; r < rounds; r++) {
        int op = (int)(rnd() % 6);
        if (op == 0 && m) out[rnd() % m] ^= (uint8_t)(1u << (rnd() % 8));       /* bit flip */
        else if (op == 1 && m) out[rnd() % m] = (uint8_t)rnd();                  /* byte set */
        else if (op == 2 && m < cap) { size_t p = rnd() % (m + 1);               /* insert */
            memmove(out + p + 1, out + p, m - p); out[p] = (uint8_t)rnd(); m++; }
        else if (op == 3 && m > 1) { size_t p = rnd() % m;                       /* erase */
            memmove(out + p, out + p + 1, m - p - 1); m--; }
        else if (op == 4 && dict_n && cap) {                                     /* dict insert */
            size_t d = rnd() % dict_n, L = dict_len[d]; if (L > cap) L = cap;
            size_t p = m ? rnd() % m : 0; if (p + L > cap) p = 0;
            if (p + L <= cap) { if (m > p) memmove(out + p + L, out + p, (m - p > cap - p - L ? cap - p - L : m - p));
                memcpy(out + p, dict[d], L); if (m + L <= cap) m += L; else m = cap; } }
        else if (op == 5 && corp_n) {                                            /* splice */
            Unit *u = &corp[rnd() % corp_n]; size_t k = u->n ? rnd() % u->n : 0;
            size_t p = m ? rnd() % m : 0; size_t L = u->n - k; if (p + L > cap) L = cap - p;
            if (L) { memcpy(out + p, u->b + k, L); if (p + L > m) m = p + L; } }
    }
    return m;
}

/* ---- crash-guarded execution ---- */
static volatile int hf_last_crash = 0;
static int run_one(const uint8_t *d, size_t n) {
#ifdef _WIN32
    __try { LLVMFuzzerTestOneInput(d, n); return 0; }
    __except (EXCEPTION_EXECUTE_HANDLER) { hf_last_crash = GetExceptionCode(); return 1; }
#else
    LLVMFuzzerTestOneInput(d, n); return 0;
#endif
}

static double now_s(void) { return (double)clock() / CLOCKS_PER_SEC; }

int main(int argc, char **argv) {
    int secs = 60; const char *dictp = NULL, *corpdir = NULL, *crashout = ".";
    for (int i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "-max_total_time=", 16)) secs = atoi(argv[i] + 16);
        else if (!strncmp(argv[i], "-dict=", 6)) dictp = argv[i] + 6;
        else if (!strncmp(argv[i], "-artifact_prefix=", 17)) crashout = argv[i] + 17;
        else if (argv[i][0] != '-') corpdir = argv[i];
    }
    if (dictp) dict_load(dictp);
    /* seed the corpus from the directory, else a single zero unit */
    if (corpdir) {
#ifdef _WIN32
        char glob[1024]; snprintf(glob, sizeof glob, "%s\\*", corpdir);
        WIN32_FIND_DATAA fd; HANDLE h = FindFirstFileA(glob, &fd);
        if (h != INVALID_HANDLE_VALUE) { do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            char p[1024]; snprintf(p, sizeof p, "%s\\%s", corpdir, fd.cFileName);
            FILE *f = fopen(p, "rb"); if (!f) continue; fseek(f, 0, SEEK_END); long L = ftell(f);
            fseek(f, 0, SEEK_SET); uint8_t *b = (uint8_t *)malloc(L ? L : 1);
            if (fread(b, 1, L, f) == (size_t)L) corp_add(b, L); free(b); fclose(f);
        } while (FindNextFileA(h, &fd)); FindClose(h); }
#endif
    }
    if (!corp_n) { uint8_t z = 0; corp_add(&z, 1); }
    /* run the seeds once to prime coverage */
    for (size_t i = 0; i < corp_n; i++) run_one(corp[i].b, corp[i].n);
    printf("hf_winfuzz: %zu seeds, %zu dict tokens, %u edges primed, %ds budget\n",
           corp_n, dict_n, hf_edges, secs);
    fflush(stdout);

    size_t cap = 1 << 20; uint8_t *buf = (uint8_t *)malloc(cap);
    double t0 = now_s(); uint64_t execs = 0; uint32_t last_report = 0;
    while (now_s() - t0 < secs) {
        Unit *u = &corp[rnd() % corp_n];
        size_t n = mutate(u->b, u->n, buf, cap);
        uint32_t before = hf_edges;
        int crashed = run_one(buf, n);
        execs++;
        if (crashed) {
            char cp[1200]; snprintf(cp, sizeof cp, "%scrash-%llu.bin", crashout, (unsigned long long)execs);
            FILE *f = fopen(cp, "wb"); if (f) { fwrite(buf, 1, n, f); fclose(f); }
            printf("\n*** CRASH code=0x%08x execs=%llu len=%zu saved=%s ***\n",
                   (unsigned)hf_last_crash, (unsigned long long)execs, n, cp);
            fflush(stdout);
            /* keep going: record and continue exploring */
        }
        if (hf_edges > before) corp_add(buf, n);
        if (hf_edges - last_report >= 20 || (execs & 0x3ffff) == 0) {
            double dt = now_s() - t0;
            printf("#%llu edges: %u corpus: %zu exec/s: %.0f\n",
                   (unsigned long long)execs, hf_edges, corp_n, dt > 0 ? execs / dt : 0);
            fflush(stdout); last_report = hf_edges;
        }
    }
    printf("DONE execs: %llu edges: %u corpus: %zu\n",
           (unsigned long long)execs, hf_edges, corp_n);
    return 0;
}
