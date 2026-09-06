/* Standalone replay driver for winapp (application entry, file_arg channel).
 * Reads one input file and calls the harness once. For the hosts where libFuzzer's
 * compiler-rt is absent -- notably windows-arm64-msvc, which still has /fsanitize=address.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef __cplusplus
extern "C"
#endif
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int main(int argc, char **argv) {
    if (argc < 2) return 0;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return 0; }
    uint8_t *buf = (uint8_t *)malloc((size_t)n ? (size_t)n : 1);
    size_t got = fread(buf, 1, (size_t)n, f); fclose(f);
    LLVMFuzzerTestOneInput(buf, got);
    free(buf);
    return 0;
}
