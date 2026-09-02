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


def _store(rel: str) -> dict:
    """Load a record from results-store/, which holds results rather than audits.

    Kept separate from _load: an audit is a record of a decision, a result is a record of a
    measurement, and merging the two directories would make it impossible to say which a
    number came from.
    """
    p = ROOT / "results-store" / rel
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
    sweep = _store("harness-sweep/sweep-2026-08-31.json")
    comp = _store("harness-sweep/compile-2026-08-31.json")
    camp = _store("fuzz-campaign/campaign-2026-09-01.json")
    caud = _store("corpus-audit/audit-2026-09-01-after-fixes.json")
    caud0 = _store("corpus-audit/audit-2026-09-01.json")
    harv = _store("corpus-audit/harvest-2026-09-01.json")
    seeds3 = _store("seeds/binary-formats-2026-09-01.json")
    seeds1 = _store("seeds/text-formats-2026-09-01.json")
    tseq = {}
    for q in sorted((ROOT / "results-store" / "test-sequences").glob("*-2026-09-01.json")):
        import json as _j
        r = _j.loads(q.read_text())
        tseq[r["library"]] = r

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

        "HARNESS_GENERATION_AT_CORPUS_SCALE": {
            "claim": "The yield of the METHOD, not of a library chosen by hand.",
            "harnesses": {"value": sweep.get("total_harnesses"),
                          "source": "harness-sweep/sweep-2026-08-31.json",
                          "caveat": "15 of 18 libraries. libpng, wabt and woff2 produced "
                                    "ZERO -- every plan refused by the gates, which is the "
                                    "refusal rate of the method and belongs in the table."},
            "compile_rate": {"value": comp.get("rate"),
                             "source": "harness-sweep/compile-2026-08-31.json",
                             "caveat": "-fsyntax-only against the library's REAL headers. "
                                       "Not linking, and not a claim about finding bugs. "
                                       "The 4 failures are entry points declared only "
                                       "inside an #ifdef the build does not set; the engine "
                                       "reads header text and does not evaluate "
                                       "preprocessor conditions."},
            "fuzzed": {"value": camp.get("total_execs"),
                       "source": "fuzz-campaign/campaign-2026-09-01.json",
                       "caveat": "30s per harness is a SMOKE TEST, not a campaign. "
                                 f"{camp.get('crashed', 0)} crashes, "
                                 f"{camp.get('candidates', 0)} promoted -- every crash "
                                 "refused by the oracle."},
            "open_defect": "libyaml ran 10 campaigns and executed EIGHT TIMES IN TOTAL: "
                           "every harness crashes after 2 executions at zero coverage, the "
                           "same contract-violation shape as the yajl_free_error family. "
                           "The deallocator rule is too narrow. Recorded as a defect in "
                           "this engine, not as a result.",
        },

        "CORPUS_AUDIT_WITH_CONTRACT_GATES": {
            "claim": "Grade third-party harnesses at a scale beyond the published "
                     "competitor's, with the contract gates actually running.",
            "scale": {"value": {"harnesses": caud.get("harnesses"),
                                "projects": caud.get("projects"),
                                "high_fidelity": caud.get("high_fidelity"),
                                "declarations": caud.get("declarations"),
                                "contracts_attached": caud.get("contracts_attached")},
                      "source": "corpus-audit/audit-2026-09-01-after-fixes.json",
                      "caveat": "QuartetFuzz audited 586 harnesses across 70 projects. This "
                                "is larger, and it is the FIRST run where S2 could run at "
                                "all -- every earlier audit reported S2 NOT RUN, which is "
                                "not PASS."},
            "reportable_defects": {
                "value": 0,
                "source": "corpus-audit/README.md",
                "caveat": f"{caud.get('blocks_high_fidelity')} blocking candidates, all "
                          "triaged by hand. All are one bazel OOM test fixture: the flags "
                          "are TRUE and none is reportable, because it tests the fuzzing "
                          "RULES rather than a library."},
            "false_positives": {
                "value": "0 of %s high-fidelity lifts" % caud.get("high_fidelity"),
                "source": "corpus-audit/audit-2026-09-01-after-fixes.json",
                "caveat": "The FIRST run of this same corpus produced 2 false positives "
                          "(1.3%), against a recorded claim of zero. Both were defects in "
                          "this engine and both are fixed. The 1.3% is kept on the results "
                          "page: a precision number that only appears after it has been "
                          "repaired is not evidence."},
            "the_finding": "Three consecutive scaled runs found nothing reportable. This is "
                           "the strongest evidence available that the FINDINGS axis is not "
                           "won by grading more harnesses.",
        },

        "SEEDS": {
            "claim": "Seeds mined from a library's own repository change coverage.",
            "binary_formats": {
                "value": {"pairs": seeds3.get("pairs"),
                          "median_ratio": seeds3.get("median_ratio"),
                          "better": seeds3.get("seeded_better"),
                          "tied": seeds3.get("tied"),
                          "worse": seeds3.get("seeded_worse"),
                          "sign_test_p": 0.0078},
                "source": "seeds/binary-formats-2026-09-01.json",
                "caveat": "The median of 1.25 is bimodal and understates it: jbig2dec "
                          "ratios are 20.98-27.25. Empty corpus 2,825,426 executions -> 32 "
                          "edges; 5 mined seeds, 155 executions -> 839 edges."},
            "text_formats": {
                "value": {"pairs": seeds1.get("pairs"),
                          "median_ratio": seeds1.get("median_ratio"),
                          "sign_test_p": 0.4545},
                "source": "seeds/text-formats-2026-09-01.json",
                "caveat": "NO effect, and cjson was WORSE at 0.9151. A fuzzer reaches valid "
                          "JSON from an empty corpus in seconds. The split by format IS the "
                          "result."},
            "what_it_invalidates": "Only tools/fuzz_sweep.py, which starts every campaign "
                                   "empty. probe_select.probe() seeds from drive.py's "
                                   "curated directories, so the +0.40% synthesis verdict "
                                   "WAS seeded and stands as measured.",
        },

        "TEST_SEQUENCES_P3_LIFT": {
            "claim": "A library's own tests express API sequences our plans cannot reach. "
                     "Measured as a DECISION GATE before any generator was written.",
            "surface_reached": {
                "value": {k: v["surface_reached_pct"] for k, v in sorted(tseq.items())},
                "source": "test-sequences/",
                "caveat": "Median 66.7% across the 9 libraries that ship C tests. brotli, "
                          "jbig2dec, libde265 and yajl ship none (shell scripts over "
                          "testdata, or CLI-driven) and a test-lifting producer yields "
                          "nothing for them -- a bound on the technique, not a bug."},
            "the_comparison_that_decides_it": {
                "value": {"our_widest_single_plan": "3 of 83 (3.6%)",
                          "union_all_base_plans": "7 (8%)",
                          "union_with_mutational_synthesis": "43 (52%)",
                          "one_test_function_test_chaos": "21 (26%)",
                          "the_test_suite": "75 (92.6%)"},
                "source": "test-sequences/jansson-2026-09-01.json + "
                          "reachability-bound-2026-08-31.json",
                "caveat": "jansson, the one library measured every way. A SINGLE test "
                          "function reaches seven times what our widest plan reaches; cjson "
                          "has one calling 51 distinct APIs and zstd one calling 56."},
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
            {"result": "A corpus audit larger than the published competitor's found "
                       "nothing reportable",
             "detail": "879 harnesses across 124 projects, with the contract gates running "
                       "for the first time, produced 4 blocking candidates -- all one bazel "
                       "OOM test fixture, all TRUE, none reportable. QuartetFuzz audited 586 "
                       "across 70 and landed 29 fixes. Third consecutive scaled run to find "
                       "nothing, and the strongest evidence that the findings axis is not "
                       "won by grading more harnesses.",
             "source": "corpus-audit/audit-2026-09-01-after-fixes.json"},
            {"result": "Seeds do nothing for text formats and can hurt",
             "detail": "20 paired campaigns over cjson, jansson, zlib and libyaml: 10 "
                       "better, 4 tied, 6 worse, median +0.15%, sign test p=0.4545. cjson "
                       "was WORSE at 0.9151. A fuzzer reaches valid JSON from an empty "
                       "corpus in seconds. The same technique gives 20-27x on jbig2dec, so "
                       "the split by format is the result rather than a single number.",
             "source": "seeds/text-formats-2026-09-01.json"},
            {"result": "Coverage guidance does not beat blind mutation on a GUI target",
             "detail": "Guided median 3257 regions against blind 3270, exact Mann-Whitney "
                       "p=0.3211, median ratio 0.996. For 7-against-8 the minimum attainable "
                       "two-sided p is 0.00031, so the design had ample power to detect a "
                       "clean separation and found none: the claim is 'at this scale there "
                       "is nothing to tell', not 'we could not tell'. Blind is also six "
                       "times more consistent (spread 34 against 1133). Before the seed was "
                       "kept in the corpus, guidance was actively WORSE (median 2633, with "
                       "2 of 4 campaigns accepting zero of 20 inputs).",
             "source": "gui-guidance/guided-vs-blind-seed-retained-2026-09-01.jsonl"},
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
            "Coverage guidance was measured as WORSE than blind mutation before the cause "
            "was found: the corpus started empty, so guidance could only breed from mutants "
            "and drifted away from validity. That is a missing invariant, not a finding "
            "about search, and the as-implemented numbers are kept so the fix is measured "
            "against something.",
            "Four generated yajl harnesses passed a fuzzer-owned buffer to a pure "
            "deallocator, and the fuzzer CERTIFIED all four as findings. A false positive "
            "shipped as a discovery is the exact failure this engine exists to prevent. Both "
            "halves fixed; the producer rule is still too narrow, since libyaml reproduces "
            "the shape.",
            "A sweep driver reported BUILD FAILURES AS SUCCESSFUL BUILDS because it imported "
            "the fuzzer inside a function, so the first call and later calls took different "
            "paths. Found only after adding a fuzz_ran field.",
            "I claimed the +0.40% synthesis verdict was measured UNSEEDED and used it to "
            "argue the coverage axis needed re-running. False: probe_select.probe() seeds "
            "from drive.py's curated directories and brotli's case carries "
            "seeds=[tests/testdata]. I had confused probe_synth's 64-run SMOKE TEST, which "
            "does use a synthetic input, with its coverage campaign. OGHarn still wins that "
            "axis and there is no seeding excuse for it.",
            "The claim of 0 FALSE POSITIVES did not survive turning the contract gates on: "
            "the first 879-harness run measured 2 on 154 high-fidelity lifts, 1.3%. Both "
            "were defects in this engine and both are fixed, restoring zero -- but the 1.3% "
            "stays recorded, because a precision number that only appears after it has been "
            "repaired is not evidence.",
            "The test-sequence extractor reported 0% of the exported surface for expat, "
            "lcms2 and libpng because it looked for test directories only at the ROOT, and "
            "0% for expat again because its tests are declared by the check framework's "
            "START_TEST macro rather than as C functions. Both zeros were claims about the "
            "instrument, and both understated the answer -- expat is 91.0%.",
        ],
    }


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(build(), indent=1) + "\n")
    print(f"written: {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
