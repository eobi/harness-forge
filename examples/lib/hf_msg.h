/* hf_msg — a tiny demonstration MESSAGING library for Harness Forge.
 *
 * It exists so the mobile message-surface producer can be exercised end to end on a clean
 * clone with nothing but a C compiler (and, for the on-device path, the NDK / a booted
 * simulator). It models the two attack surfaces a modern messaging app exposes to an
 * attacker who only has to send a message:
 *
 *   (a) SMS / PDU PARSING. `sms_pdu_decode` takes the raw bytes of a GSM 03.40 TPDU — the
 *       thing that arrives over the air — and walks its header. This is the surface that a
 *       malformed SMS/USSD/WAP-push exercises, reachable with zero user interaction.
 *
 *   (b) ATTACHMENT / MEDIA DECODING. A received MMS or rich message carries an attachment
 *       that a decoder unpacks the instant it arrives — the Stagefright / libwebp
 *       zero-click shape. `mms_container_parse` reads the container header and the
 *       `mms_image_decode_*` / `mms_thumb_info` calls decode the payload. They all take the
 *       SAME (bytes, len), so folding them onto one input reaches the union of their code —
 *       exactly what the codec-composition path is for.
 *
 * Every entry point here is BOUNDED and contract-clean: the demo proves the pipeline
 * (discover -> emit -> cross-build -> push -> run -> differential), not a planted finding.
 */
#ifndef HF_MSG_H
#define HF_MSG_H

#include <stddef.h>
#include <stdint.h>

/* ── (a) SMS / PDU parsing surface ─────────────────────────────────────────── */

/* Decode a GSM 03.40 SMS-DELIVER TPDU from its raw bytes. Reads exactly `len` bytes and
 * never past them. Returns the number of user-data septets it accounted for, or -1 on a
 * malformed PDU. This is the over-the-air SMS attack surface. */
int sms_pdu_decode(const unsigned char *pdu, size_t len);

/* Unpack a 7-bit GSM default-alphabet user-data field into `out` (caller sizes it via the
 * return of sms_pdu_decode). Length-delimited; reads exactly `len` bytes. */
int sms_ud_7bit_unpack(const unsigned char *ud, size_t len);

/* ── (b) attachment / media decoding surface (the codec-compose family) ─────── */

/* Parse an MMS attachment container header (magic + dimensions + payload offset). Bounded.
 * Returns 0 on a well-formed header, -1 otherwise. */
int mms_container_parse(const unsigned char *data, size_t size);

/* Decode an attachment image to RGBA. Bounded to `size`. Returns 0 on success. */
int mms_image_decode_rgba(const unsigned char *data, size_t size);

/* Decode an attachment image to 8-bit grayscale. Bounded to `size`. Returns 0 on success. */
int mms_image_decode_gray(const unsigned char *data, size_t size);

/* Read just the thumbnail dimensions from an attachment (a shallow header query). */
int mms_thumb_info(const unsigned char *data, size_t size);

#endif /* HF_MSG_H */
