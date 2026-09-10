"""Discover a messaging app's zero-interaction attack surface and emit a harness for it.

The mobile analogue of `app_lift`: a messaging application is attacked through the messages
it RECEIVES, and two shapes carry almost every zero-click bug of the last decade:

  (a) SMS / PDU PARSING. A malformed SMS-DELIVER TPDU, USSD string or WAP-push arrives over
      the air and is parsed before any user sees it. The entry point is a `(bytes, len)`
      decoder over the raw PDU.

  (b) ATTACHMENT / MEDIA DECODING. A received MMS or rich message carries an attachment that
      a container parser and one or more media decoders unpack the instant it lands — the
      Stagefright / libwebp zero-click shape. These decoders all take the SAME `(bytes, len)`,
      so folding them onto one input reaches the union of their code. That is exactly what
      `app_lift.compose_app` already does, so this producer REUSES it rather than reinventing
      the fold, `AppEntry.fold` / `config_fields` / `app_seq` and all.

This producer is `app_lift` tuned for that surface. The tuning is three things:

  1. it recognises SMS/PDU vs attachment/media entry points BY NAME, so the harness drives the
     message parser rather than whatever happens to rank highest in a general header;
  2. it defaults the plan's `platforms` to the mobile targets (Android emulator + iOS
     Simulator), so the platform-aware emitter cross-builds instead of emitting a host build;
  3. it separates the two surfaces so a caller can target either.

It PROPOSES, exactly like every producer. The gates and the ladder certify; nothing here does.
No IR schema change: `HarnessIR.platforms` + `AppEntry` already carry everything.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..ir import HarnessIR, Target
from . import app_lift

PRODUCER = "message_surface"

# The mobile targets a received-message harness is meant to run on. Android is the discovery
# platform (cheap instrumentation); the iOS Simulator is the reachability oracle. The
# platform-aware emitter routes each to its cross-compile backend.
DEFAULT_PLATFORMS = ["android-arm64-emulator", "ios-arm64-simulator"]

# (a) SMS / PDU / short-message parsing. Deliberately anchored on the vocabulary of the
# over-the-air message formats, not generic "parse".
_SMS_RE = re.compile(
    r"(?:^|_)(sms|pdu|tpdu|gsm7|gsm_?7|7bit|septet|ussd|smsc|deliver|submit|"
    r"rp_?data|tp_?du|ucs2|nbs|wsp|wap_?push|cbs|cell_?broadcast|short_?message|"
    r"telephony|message_?decode|decode_?message|parse_?message|msg_?parse)", re.I)

# (b) attachment / media / container decoding — the zero-click codec surface.
_MEDIA_RE = re.compile(
    r"(?:^|_)(attach|attachment|mms|media|image|img|thumb|thumbnail|sticker|avatar|"
    r"container|demux|mux|track|sample|frame|codec|decode|heif|heic|hevc|avif|webp|gif|"
    r"jpe?g|jp2|png|bmp|tiff|mp4|m4a|amr|aac|mkv|ogg|opus|vcard|vcf)", re.I)


def surface_of(symbol: str) -> str:
    """Which messaging surface a symbol belongs to: 'sms', 'media', or '' (neither).

    SMS wins ties: an `sms_media_*` helper is part of the message parser, not the codec.
    """
    if _SMS_RE.search(symbol or ""):
        return "sms"
    if _MEDIA_RE.search(symbol or ""):
        return "media"
    return ""


def discover(headers: list, includes: tuple = ()) -> dict:
    """Ranked candidates from a header, split by messaging surface.

    Reuses `app_lift.discover` (same signature-based channel classification and ranking), then
    partitions the result. Returns {'sms': [...], 'media': [...], 'other': [...], 'all': [...]}.
    """
    cands = app_lift.discover(headers, includes)
    out = {"sms": [], "media": [], "other": [], "all": cands}
    for c in cands:
        out.get(surface_of(c["symbol"]) or "other", out["other"]).append(c)
    return out


def _foldable_media(disc: dict) -> list:
    """Media/attachment candidates that are safe (buffer,size) decoders — the fold family."""
    fam = []
    for c in disc["media"]:
        if c["channel"] == app_lift.APP_BUFFER and c.get("call_args") \
                and not c.get("has_out_buffer") and not c.get("out_scratch"):
            fam.append(c)
    return fam


def _resolve_surface(disc: dict, requested: str) -> str:
    if requested and requested != "auto":
        return requested
    # auto: prefer the SMS/PDU parser when one exists (it is the canonical zero-interaction
    # entry); otherwise the attachment/media fold when there is a family to compose.
    if disc["sms"]:
        return "sms"
    if len(_foldable_media(disc)) >= 2:
        return "media"
    if disc["media"]:
        return "media"
    return "sms"          # nothing recognised; let the sms path report the honest why-not


def propose(headers: list, target: Target, includes: tuple = (), only: str = "",
            surface: str = "auto", platforms=None) -> tuple:
    """(HarnessIR or None, record). Emit a harness for the chosen messaging surface.

    `surface` is 'sms', 'media', or 'auto'. `only` names a single symbol to lift (implies the
    single-entry path). `platforms` overrides the default mobile targets.
    """
    plats = list(platforms) if platforms else list(DEFAULT_PLATFORMS)
    # app_lift reads platforms off the target (getattr with a default), so put them there.
    target.platforms = plats

    disc = discover(headers, includes)
    chosen_surface = "sms" if only else _resolve_surface(disc, surface)
    rec: dict = {"producer": PRODUCER, "surface": chosen_surface, "platforms": plats,
                 "sms_candidates": [c["symbol"] for c in disc["sms"]],
                 "media_candidates": [c["symbol"] for c in disc["media"]]}

    if chosen_surface == "media":
        plan, crec = app_lift.compose_app(headers, target, includes=includes)
        rec.update({k: v for k, v in crec.items() if k not in ("producer",)})
        if plan is None:
            rec["why_not"] = crec.get(
                "why_not", "no attachment/media decode family (need >=2 safe (bytes,len) "
                           "decoders to fold onto one input)")
            return None, rec
        plan.producer = PRODUCER
        plan.platforms = plats
        plan.name = f"{target.name}_msg_attach"[:60]
        rec["chosen"] = crec.get("chosen", {})
        return plan, rec

    # SMS / PDU single-entry path. Restrict to recognised SMS entries and pick the best.
    if only:
        sym = only
    else:
        sms = disc["sms"]
        if not sms:
            rec["why_not"] = ("no SMS/PDU parse entry point recognised (no (bytes,len) "
                              "decoder whose name names an SMS/PDU/short-message format). "
                              f"Try --surface media, or --only <symbol>. "
                              f"Candidates seen: {[c['symbol'] for c in disc['all']][:8]}")
            return None, rec
        sym = sms[0]["symbol"]

    plan, prec = app_lift.propose(headers, target, includes=includes, only=sym)
    rec["app_lift_candidates"] = prec.get("candidates", [])
    if plan is None:
        rec["why_not"] = prec.get("why_not", f"could not lift {sym!r} as an entry point")
        return None, rec
    plan.producer = PRODUCER
    plan.platforms = plats
    plan.name = f"{target.name}_msg_sms_{sym}"[:60]
    rec["chosen"] = {**prec.get("chosen", {}), "surface": "sms"}
    return plan, rec
