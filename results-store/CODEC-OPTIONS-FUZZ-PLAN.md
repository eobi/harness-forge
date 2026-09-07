# #3: fuzzing decode options (the last gap to beating the dev harness) — 2026-09-07

## Where it stands
#1 (auto-compose) and #2 (generalize) are done and committed: `hforge app-lift --compose`
auto-generates the folded codec harness, measured 0.92x the simple dev harness on libwebp and
+7-10% over single-entry on libwebp/stb_image. The remaining gap to the HAND-written 1.29x
result is decode OPTIONS: the hand harness set config.options.{flip,crop,scale,colorspace}
from input bytes; the auto one calls WebPDecode with a zeroed (default) config.

## Why it is not a quick patch
WebPDecoderConfig = { input (scalars), output (WebPDecBuffer -- HAS POINTERS), options
(scalars) }. Byte-blasting the whole config corrupts output's pointers -> crash. The safe move
is to set ONLY config.options's scalar fields from input bytes. That needs FIELD ENUMERATION
of the options sub-struct, which header_graph does not expose today (it has `complete` type
names and `req_init`, but not full struct field lists).

## The scoped feature to build
1. header_graph: parse struct bodies -> `struct_fields(type) -> [(ctype, name)]`, recursively,
   flagging pointer/union members as unfuzzable.
2. compose_app: when a decode entry takes a config struct that (a) has a paired init function
   (WebPInitDecoderConfig) and (b) contains a pointer-free scalar sub-struct (options), emit a
   "config-fuzz" entry: init(config); set each scalar option field from consecutive input
   bytes; decode; free the output buffer.
3. emitter: a config-fuzz block (init + field assignments from a byte cursor + call).

## Measured target
Hand-written proof: composed+options = 2366 edges = 1.29x the simple dev harness (past
OGHarn's 1.14x bar); the auto harness without options is 1694 (0.92x). Closing this makes the
AUTO harness cross the bar, not just the hand-written one.
