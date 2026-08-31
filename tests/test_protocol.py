#!/usr/bin/env python3
"""Corpus-mined API ordering conventions, and the filters that keep them honest."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import protocol  # noqa: E402


def _corpus(n_ok: int, violator_seq=None):
    seqs = [(f"ok{i}.c", ["lib_new", "lib_use", "lib_free"]) for i in range(n_ok)]
    if violator_seq is not None:
        seqs.append(("bad.c", violator_seq))
    return seqs


def test_it_finds_a_convention_and_its_exception():
    rules = protocol.mine(_corpus(10, ["lib_free"]), min_support=4)
    assert rules and rules[0]["before"] == "lib_new"
    assert "bad.c" in rules[0]["violators"]


def test_a_pair_must_share_a_module():
    """`sprintf -> pcap_close` appears 132 times in one order and is not a protocol; it is
    alphabetical accident. Without this filter the tool is a co-occurrence generator."""
    seqs = [(f"x{i}.c", ["sprintf", "pcap_close"]) for i in range(10)]
    seqs.append(("bad.c", ["pcap_close"]))
    assert protocol.mine(seqs, min_support=4) == []


def test_the_earlier_call_must_be_an_initialiser():
    """`pixReadMemSpix -> pixDestroy` holds 276 times, and the harnesses that break it read
    their image with a different function. That is a second way to do the same thing, not a
    protocol violation."""
    seqs = [(f"x{i}.c", ["pix_read", "pix_destroy"]) for i in range(10)]
    seqs.append(("bad.c", ["pix_destroy"]))
    assert protocol.mine(seqs, min_support=4) == []


def test_any_initialiser_of_the_module_counts():
    """A library has more than one constructor. dropbear builds its buffer with
    `buf_getstringbuf` and frees it with `buf_free`; keyed on `buf_new` alone that reads as
    freeing something it never made."""
    seqs = [(f"x{i}.c", ["buf_new", "buf_free"]) for i in range(10)]
    seqs.append(("alt.c", ["buf_create", "buf_free"]))
    rules = protocol.mine(seqs, min_support=4)
    assert all("alt.c" not in r["violators"] for r in rules), rules


def test_a_rate_alone_would_discard_a_small_denominator():
    """`buf_new -> buf_free` holds 24 times but only 9 harnesses call buf_free at all, so
    two exceptions are 22% and a rate filter drops the rule. Few exceptions in ABSOLUTE
    terms is the signal when the denominator is small."""
    seqs = [(f"x{i}.c", ["lib_new", "lib_free"]) for i in range(7)]
    seqs += [("b1.c", ["lib_free"]), ("b2.c", ["lib_free"])]
    rules = protocol.mine(seqs, min_support=4, max_violation_rate=0.01)
    assert rules and rules[0]["violations"] == 2


def test_untrusted_lifts_are_refused_by_default():
    """pjsip calls `pj_init()` inside an `if` condition. On an untrusted sequence it looked
    like using pjlib without initialising it -- a defect in the lifter, which the lifter
    already reports. Mining those is mining our own blind spots."""
    import inspect
    sig = inspect.signature(protocol.read_corpus)
    assert sig.parameters["trusted_only"].default is True
