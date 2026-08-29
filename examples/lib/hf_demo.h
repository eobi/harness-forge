/* hf_demo — a tiny demonstration library for Harness Forge.
 *
 * It exists so the engine can be exercised end to end on a clean clone with nothing but a
 * C compiler. Two parse entry points, deliberately:
 *
 *   hd_parse    takes a NUL-TERMINATED string. Feeding it an exact-size buffer makes the
 *               library read past the end of EVERY input. That is not a bug in hd_parse;
 *               it is the caller violating the contract, and it is exactly what happened
 *               to a real cJSON harness that then produced eight false reports.
 *
 *   hd_parse_n  takes an explicit (pointer, length) pair and reads nothing past it.
 *
 * Gate S2 tells those two apart from the plan alone, without compiling anything.
 */
#ifndef HF_DEMO_H
#define HF_DEMO_H

#include <stddef.h>
#include <stdint.h>

typedef struct hd_ctx hd_ctx;

/* Creates a parser context. Returns NULL on allocation failure. */
hd_ctx *hd_open(void);

/* CONTRACT: `json` must be NUL-terminated. Returns node count, or -1 on error. */
int hd_parse(hd_ctx *c, const char *json);

/* Length-delimited variant. Reads exactly `n` bytes and no more. */
int hd_parse_n(hd_ctx *c, const uint8_t *buf, size_t n);

/* Tolerates NULL. */
void hd_close(hd_ctx *c);

/* Depth reached by the last parse. */
int hd_depth(const hd_ctx *c);

#endif /* HF_DEMO_H */
