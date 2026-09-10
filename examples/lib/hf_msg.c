/* hf_msg — implementation. Deliberately bounded and contract-clean (see hf_msg.h). */
#include "hf_msg.h"

/* ── (a) SMS / PDU parsing ─────────────────────────────────────────────────── */

int sms_ud_7bit_unpack(const unsigned char *ud, size_t len) {
    /* Count set bits across the field — a stand-in for real septet unpacking. Reads exactly
     * `len` bytes, no terminator assumed, nothing past the end. */
    int bits = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char b = ud[i];
        while (b) { bits += b & 1; b >>= 1; }
    }
    return bits;
}

int sms_pdu_decode(const unsigned char *pdu, size_t len) {
    /* GSM 03.40 SMS-DELIVER, walked defensively. Every field access is guarded against the
     * declared length before it is read. */
    size_t off = 0;
    if (len < 1) return -1;

    unsigned char smsc_len = pdu[off++];          /* SMSC info length */
    if (smsc_len > len - off) return -1;
    off += smsc_len;                               /* skip SMSC address */

    if (off >= len) return -1;
    /* first octet (message type, etc.) */
    off++;

    if (off >= len) return -1;
    unsigned char oa_len = pdu[off++];             /* originating-address digit count */
    size_t oa_octets = (size_t)(oa_len + 1) / 2;   /* semi-octet packing */
    if (off >= len) return -1;
    off++;                                          /* type-of-address */
    if (oa_octets > len - off) return -1;
    off += oa_octets;

    if (len - off < 3) return -1;
    off += 1;                                       /* protocol identifier */
    off += 1;                                       /* data coding scheme  */
    off += 1;                                       /* one octet of timestamp we sample */

    if (off >= len) return -1;
    unsigned char udl = pdu[off++];                 /* user-data length (septets) */
    size_t ud_octets = ((size_t)udl * 7 + 7) / 8;   /* 7-bit packing -> octets */
    if (ud_octets > len - off) ud_octets = len - off;   /* clamp to what we actually have */

    (void)sms_ud_7bit_unpack(pdu + off, ud_octets);
    return (int)udl;
}

/* ── (b) attachment / media decoding ───────────────────────────────────────── */

/* Shared 12-byte container header: 4 magic, 2 width, 2 height, 4 payload-offset. */
static int mms_header(const unsigned char *data, size_t size,
                      unsigned *w, unsigned *h, size_t *payload) {
    if (size < 12) return -1;
    if (!(data[0] == 'M' && data[1] == 'M' && data[2] == 'S' && data[3] == '1')) return -1;
    *w = (unsigned)data[4] | ((unsigned)data[5] << 8);
    *h = (unsigned)data[6] | ((unsigned)data[7] << 8);
    size_t off = (size_t)data[8] | ((size_t)data[9] << 8)
               | ((size_t)data[10] << 16) | ((size_t)data[11] << 24);
    if (off > size) return -1;
    *payload = off;
    return 0;
}

int mms_container_parse(const unsigned char *data, size_t size) {
    unsigned w, h; size_t payload;
    return mms_header(data, size, &w, &h, &payload);
}

int mms_image_decode_rgba(const unsigned char *data, size_t size) {
    unsigned w, h; size_t payload;
    if (mms_header(data, size, &w, &h, &payload) != 0) return -1;
    /* Walk the payload the header points at, bounded by the true size. A real decoder would
     * emit 4 bytes/pixel; here we just fold the bytes so the code path is exercised. */
    unsigned long acc = 0;
    for (size_t i = payload; i < size; i++) acc = (acc << 1) ^ data[i];
    (void)w; (void)h;
    return (int)(acc & 0x7fffffff);
}

int mms_image_decode_gray(const unsigned char *data, size_t size) {
    unsigned w, h; size_t payload;
    if (mms_header(data, size, &w, &h, &payload) != 0) return -1;
    unsigned long acc = 0;
    for (size_t i = payload; i < size; i++) acc += data[i];
    (void)w; (void)h;
    return (int)(acc & 0x7fffffff);
}

int mms_thumb_info(const unsigned char *data, size_t size) {
    unsigned w, h; size_t payload;
    if (mms_header(data, size, &w, &h, &payload) != 0) return -1;
    return (int)((w & 0xffff) | (h << 16));
}
