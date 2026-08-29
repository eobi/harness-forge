#include "hf_demo.h"

#include <stdlib.h>
#include <string.h>

struct hd_ctx {
    int depth;
    int max_depth;
    size_t nodes;
};

hd_ctx *hd_open(void) {
    return (hd_ctx *)calloc(1, sizeof(hd_ctx));
}

void hd_close(hd_ctx *c) {
    free(c);
}

int hd_depth(const hd_ctx *c) {
    return c ? c->max_depth : -1;
}

static int hd_scan(hd_ctx *c, const char *p, size_t n) {
    size_t i;
    int depth = 0, max = 0;
    size_t nodes = 0;

    for (i = 0; i < n; i++) {
        switch (p[i]) {
        case '[':
        case '{':
            depth++;
            if (depth > max) max = depth;
            break;
        case ']':
        case '}':
            if (depth == 0) return -1;   /* unbalanced */
            depth--;
            break;
        case ',':
            nodes++;
            break;
        default:
            break;
        }
    }
    if (depth != 0) return -1;
    c->depth = depth;
    c->max_depth = max;
    c->nodes = nodes;
    return (int)nodes;
}

/* CONTRACT: `json` must be NUL-terminated.
 * strlen() is where a non-terminated buffer over-reads, and it over-reads on EVERY input,
 * not on an interesting one. A harness that feeds this an exact-size buffer turns a correct
 * library into an infinite source of false findings. */
int hd_parse(hd_ctx *c, const char *json) {
    if (!c || !json) return -1;
    return hd_scan(c, json, strlen(json));
}

int hd_parse_n(hd_ctx *c, const uint8_t *buf, size_t n) {
    if (!c || (!buf && n)) return -1;
    return hd_scan(c, (const char *)buf, n);
}
