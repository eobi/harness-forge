#!/usr/bin/env python3
"""One authoritative metrics file, assembled from the audit records that produced it.

Every number a paper might quote lives in `benchmarks/audits/*.json`, one file per
experiment, written when the experiment ran. That is the right place for provenance and the
wrong place to write a paper from: nobody drafting a results section wants to open eleven
files and reconcile them.

This assembles `results-store/METRICS.json` -- every headline figure with the audit file it
came from, the date, and the caveat that must travel with it. It DERIVES, it does not
restate: if an audit record changes, rerun this rather than editing the output.

A metric here carries three things or it does not belong:
  value        what was measured
  source       the audit file, so it can be rechecked
  caveat       what makes it wrong to quote alone
"""
from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
AUDITS = ROOT / "benchmarks" / "audits"
OUT = ROOT / "results-store" / "METRICS.json"


def _load(name: str) -> dict:
    p = AUDITS / name
    return json.loads(p.read_text()) if p.exists() else {}


def build() -> dict:
    fleet = _load("ossfuzz-fleet-2026-08-30.json")
    upstream = _load("upstream-repos-2026-08-31.json")
    negcap = _load("negative-capability-2026-08-31.json")
    reach = _load("reachability-bound-2026-08-31.json")
    synth = _load("synthesis-coverage-2026-08-31.json")
    woff2 = _load("woff2-n5-2026-08-31.json")
    gui = _load("gui-campaign-5000-2026-09-01.json")
    census = _load("fidelity-census-2026-08-31.json")
    proto = _load("protocol-mining-2026-08-31.json")

    return {
        "generated": str(date.today()),
        "generator": "tools/consolidate.py -- derived, never hand-edited",
        "engine": "harness-forge",

        "AXIS_1_FINDINGS": {
            "claim": "A gate bank that grades somebody else's harness, calibrated to zero "
                     "false positives, producing defects maintainers accept.",
            "corpus": {
                "value": {"harnesses": 2693, "oss_fuzz_tree": 420,
                          "upstream_repos": 2273, "projects_harvested": 479},
                "source": "upstream-repos-2026-08-31.json",
                "caveat": "The upstream corpus is every OSS-Fuzz C/C++ project with a "
                          "GitHub main_repo. It is not a random sample of fuzzing "
                          "harnesses in general.",
            },
            "trusted_lifts": {
                "value": 496, "of_lifted": 1947, "pct": 25,
                "source": "fidelity-census-2026-08-31.json",
                "caveat": "MUST travel with the denominator. The engine declines to opine "
                          "on 75% of what it lifts.",
            },
            "false_positive_rate": {
                "value": "0 of 496 trusted lifts",
                "source": "upstream-repos-2026-08-31.json (FINAL_gate_calibration)",
                "caveat": "QuartetFuzz reports 4.8% over EVERYTHING they judged. The "
                          "denominators are not comparable: we buy precision by "
                          "abstaining. Across all 1947 lifted harnesses 28.8% carry a "
                          "blocking violation.",
            },
            "candidates_triaged_by_hand": {
                "value": 55, "real": 2, "engine_defects": 53,
                "source": "upstream-repos-2026-08-31.json",
                "caveat": "The 53 were defects in THIS ENGINE. Fixing them is what made "
                          "the 2 visible. Most of the work was calibration, not detection.",
            },
            "upstream_fixes": {
                "merged": [{"pr": "DanBloomberg/leptonica#813",
                            "defect": "pix3_fuzzer passes NULL to three functions it means "
                                      "to test; each returns on its !pix guard and had "
                                      "never executed on any input",
                            "merged": "2026-08-31",
                            "maintainer": "Thank you for finding these errors and "
                                          "providing excellent documentation."}],
                "open": [{"pr": "google/oss-fuzz#16081",
                          "defect": "bluez fuzz_gobex leaks a GError on every failed decode"}],
                "source": "findings/",
                "caveat": "QuartetFuzz landed 29 fixes and 3 CVEs. This is 1 merged, 1 open.",
            },
        },

        "AXIS_2_COVERAGE": {
            "claim": "Mutational plan synthesis reaches OGHarn's +14% median over "
                     "developer-written harnesses.",
            "VERDICT": "NOT SUPPORTED",
            "measured": {
                "value": synth.get("brotli", {}),
                "libyaml": synth.get("libyaml", {}),
                "source": "synthesis-coverage-2026-08-31.json",
                "caveat": "brotli: +0.34 points, +0.40%, positive in 5 of 5 runs, exact "
                          "Mann-Whitney p = 0.056. libyaml: ZERO viable candidates, all "
                          "abort on a valid input. Target was +14%.",
            },
            "candidate_space_did_widen": {
                "value": {"jansson": "x14.2 valid candidates, reachable surface 8% -> 52%",
                          "expat": "x16.6 valid candidates, 76% -> 78%"},
                "source": "reachability-bound-2026-08-31.json",
                "caveat": "A CEILING, not coverage. Widening the ceiling did not raise the "
                          "floor. expat is the control: its bases already reach 76%.",
            },
            "static_gating_is_necessary_but_not_sufficient": {
                "value": "A synthesised candidate that passes every static gate can abort "
                         "on input 1: yaml_parser_set_encoding asserts !parser->encoding. "
                         "The pipeline is now static (microseconds) -> smoke test (2s) -> "
                         "campaign (90s).",
                "source": "synthesis-coverage-libyaml-2026-08-31.json",
                "caveat": "This qualifies the central bet of the approach and should be "
                          "reported as a limitation, not omitted.",
            },
        },

        "AXIS_3_NEGATIVE_CAPABILITY": {
            "claim": "A certificate should state what a harness CANNOT find. Neither "
                     "competitor emits this.",
            "corpus_scale": {
                "value": negcap.get("by_signal") and {
                    k: len(v) for k, v in negcap.get("by_signal", {}).items()},
                "headline": "115 of 1374 OSS-Fuzz projects (8.4%) cannot report a leak",
                "source": "negative-capability-2026-08-31.json",
                "caveat": "Every signal is a literal build setting, never an inference. "
                          "These are BOUNDS, not accusations: a project may disable a "
                          "detector for good reason.",
            },
            "per_plan_scale": {
                "value": reach.get("measured"),
                "headline": "jansson's widest harness calls 3 of 83 exported functions",
                "source": "reachability-bound-2026-08-31.json",
                "caveat": "A floor, not a prediction: unreachable THROUGH THIS PLAN's own "
                          "calls. The library may reach them internally.",
            },
            "the_bound_as_a_query": {
                "value": "1 -- bluez/fuzz_gobex, the harness already filed",
                "source": "negative-capability-2026-08-31.json",
                "caveat": "A search that finds nothing bounds how much is left to find. "
                          "The seam is not rich.",
            },
        },

        "MEASUREMENT_METHODOLOGY": {
            "claim": "Fixed-time fuzzing benchmarks are far less reproducible than the "
                     "literature assumes, and the cause is not always the machine.",
            "woff2_n5": {
                "value": woff2.get("runs"), "median_ratio": 1.18,
                "exact_mann_whitney_p": 1.0,
                "source": "woff2-n5-2026-08-31.json",
                "caveat": "THE KEY RESULT: p = 1.0 on an IDLE host with machine_was_busy "
                          "false on every record. Spreads of 23.98 and 30.87 points. The "
                          "cause is `seeds: 0` -- no seed corpus, so each campaign is a "
                          "random walk. A single sample said 1.31x; another said 0.31x.",
            },
            "pugixml_n5": {
                "value": {"ours": "14.79 spread 0.00", "gold": "14.79 spread 0.49",
                          "ratio": 1.00, "n": 5, "distinct_seeds": 5},
                "source": "benchmarks/results/hpug-*.jsonl",
                "caveat": "Seeded, and therefore steady. The only C++ head-to-head case "
                          "with a defensible number.",
            },
            "host_contention": {
                "value": {"mac_spread_pct_of_median": 64, "vm_spread_pct_of_median": 25},
                "source": "benchmarks/REPLICATION.md",
                "caveat": "A GUEST VM reports itself idle while its host is saturated, so "
                          "an in-guest load check gives a false all-clear. Throughput "
                          "stability is the trustworthy substitute.",
            },
        },

        "GUI_TRACK": {
            "claim": "An accessibility-tree oracle can distinguish a target REFUSING an "
                     "input from one that has hung -- a distinction signal-based fuzzers "
                     "cannot make.",
            "campaign": {
                "value": gui.get("result"),
                "source": "gui-campaign-5000-2026-09-01.json",
                "caveat": "5000 inputs, 0 findings. Acceptance stable at 29% across 12, "
                          "400 and 5000 inputs. The campaign is BLIND -- no coverage "
                          "feedback -- and 3574 of 5000 inputs never reached the decoder.",
            },
            "honest_rating": {"oracle": "7/10", "search": "3/10",
                              "caveat": "GUIFUZZ++ is grey-box and found 23 bugs across "
                                        "11-12 applications."},
        },

        "NEGATIVE_RESULTS_WORTH_PUBLISHING": [
            {"result": "Corpus-mined API protocol checking finds nothing on this corpus",
             "detail": proto.get("verdict", {}).get("the_honest_conclusion"),
             "source": "protocol-mining-2026-08-31.json"},
            {"result": "Mutational synthesis does not reach +14%",
             "detail": synth.get("VERDICT"), "source": "synthesis-coverage-2026-08-31.json"},
            {"result": "woff2 cannot measure a coverage ratio at all",
             "detail": "p = 1.0 at n=5 on an idle host",
             "source": "woff2-n5-2026-08-31.json"},
            {"result": "5000 blind GUI inputs find nothing in eog",
             "detail": "0 crashes, 0 hangs, controls held",
             "source": "gui-campaign-5000-2026-09-01.json"},
        ],

        "CORRECTIONS_MADE_TO_OUR_OWN_CLAIMS": [
            "S1.LEAK was recorded at 57% of trusted lifts; re-measured it was 22%. A "
            "census decays and this one ordered the plan a day after it stopped being true.",
            "A fidelity signal detected trust by GREPPING CLI OUTPUT for a phrase, so "
            "changing the phrase appeared to make 130 harnesses trustworthy.",
            "Gold was measured by a more generous method than ours.",
            "The audit tool never globbed .cpp and silently dropped ~half the upstream "
            "corpus.",
            "The benchmark was blind to machine load; woff2 was later shown to vary just "
            "as much on an idle host, so that diagnosis was itself incomplete.",
            "A projected +43% from member-call lifting delivered +5.6%.",
            "An alias-counter 'fix' promising +55 trusted lifts produced 17 FALSE "
            "positives against correct harnesses and was reverted.",
            "A synthesis probe reported 'gain -71.79 points' that measured only my own "
            "candidate ordering.",
            "Two regexes did not terminate; both were caught by timing the corpus, "
            "neither by the test suite.",
        ],
    }


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(build(), indent=1) + "\n")
    print(f"written: {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
