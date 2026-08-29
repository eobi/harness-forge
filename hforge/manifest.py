"""The phase manifest — what we said we would build, in machine-readable form.

A plan in a markdown file drifts from the code within a week and nobody notices, because
nothing checks it. This is the plan as data, so `tools/plancheck.py` can hold the repository
against it after every increment and fail when the two disagree.

The rule that makes it worth having: **a deliverable may only be marked DONE when something
executable proves it.** Every DONE entry names its evidence — a module, a gate id, a test
function — and plancheck verifies that evidence exists. A status field nobody checks is a
status field that lies.
"""
from __future__ import annotations

from dataclasses import dataclass, field

DONE = "done"
PARTIAL = "partial"
PLANNED = "planned"

STATUSES = (DONE, PARTIAL, PLANNED)


@dataclass(frozen=True)
class Deliverable:
    id: str
    description: str
    status: str
    # Evidence that the deliverable exists. plancheck resolves each one.
    modules: tuple = ()          # importable module paths
    gates: tuple = ()            # gate ids that must be registered
    tests: tuple = ()            # test function names that must exist and pass
    cli: tuple = ()              # CLI subcommands that must exist
    note: str = ""


@dataclass(frozen=True)
class Phase:
    id: str
    name: str
    status: str
    deliverables: tuple = ()


PHASES: tuple = (
    Phase("P1", "IR, static gates, C emitter", DONE, (
        Deliverable("P1.IR", "Harness IR schema v1 with lifetimes, contracts, knobs", DONE,
                    modules=("hforge.ir",),
                    tests=("test_ir_round_trip", "test_ir_rejects_major_version_mismatch")),
        Deliverable("P1.PLATFORM", "OS x arch x variant model with trust ceilings", DONE,
                    modules=("hforge.platform",), cli=("platforms",),
                    tests=("test_ios_device_cannot_certify_what_the_simulator_can",
                           "test_android_device_records_scudo_and_tombstones",
                           "test_variant_disagreement_is_read_as_an_oracle")),
        Deliverable("P1.STATIC", "static gates S1-S6, run before a compiler exists", DONE,
                    modules=("hforge.gates.static_gates",),
                    gates=("S1", "S2", "S3", "S4", "S5", "S6"),
                    tests=("test_s2_rejects_non_terminated_buffer_to_cstring_api",
                           "test_s1_use_after_destroy", "test_s6_unchecked_failure_return")),
        Deliverable("P1.EMIT", "C emitter for the libFuzzer backend", DONE,
                    modules=("hforge.emit.c_libfuzzer",), cli=("emit",),
                    tests=("test_emitter_terminates_cstring_slices",
                           "test_driver_uses_an_exactly_sized_heap_buffer")),
        Deliverable("P1.CERT", "certificate with surface, unreachability and trust", DONE,
                    modules=("hforge.certificate",), cli=("certify",),
                    tests=("test_certificate_states_what_the_harness_cannot_find",
                           "test_certificate_is_provisional_when_a_gate_did_not_run")),
        Deliverable("P1.DYN1", "phase-1 dynamic gates D1, D3, D5, D6, D7", DONE,
                    modules=("hforge.gates.dynamic_gates",),
                    gates=("D1", "D3", "D5", "D6", "D7")),
    )),

    Phase("P2", "dynamic gates and positive control", DONE, (
        Deliverable("P2.D2", "positive control: the harness must find a planted defect", DONE,
                    modules=("hforge.mutate", "hforge.gates.dynamic_gates"),
                    gates=("D2",),
                    tests=("test_mutation_operators_change_the_source",
                           "test_d2_blocks_a_harness_that_cannot_find_a_planted_bug")),
        Deliverable("P2.D4", "sink reachability: fraction of reachable sinks touched", DONE,
                    modules=("hforge.analysis.sinks", "hforge.gates.dynamic_gates"),
                    gates=("D4",),
                    tests=("test_sink_scanner_finds_memory_sinks",
                           "test_reachability_from_entry_points")),
        Deliverable("P2.D9", "misuse provenance: harness-allocated or library-allocated", DONE,
                    modules=("hforge.gates.dynamic_gates",), gates=("D9",),
                    tests=("test_d9_attributes_a_harness_allocated_overflow",
                           "test_d9_attributes_a_library_allocated_overflow")),
        Deliverable("P2.D8",
                    "campaign productivity: build the real fuzzer, report the edges it sees",
                    DONE,
                    modules=("hforge.gates.dynamic_gates",), gates=("D8",),
                    tests=("test_d8_flags_an_uninstrumented_target",),
                    note="a correct harness linked against a prebuilt library ran 11.7M "
                         "executions at cov:2 — random testing at high speed. Invisible to "
                         "every other gate, all of which passed."),
        Deliverable("P2.D11", "differential consistency across producers", DONE,
                    modules=("hforge.gates.dynamic_gates",), gates=("D11",),
                    tests=("test_d11_flags_disagreeing_plans",)),
        Deliverable("P2.CORPUS", "input generation so gates can exercise a harness", DONE,
                    modules=("hforge.corpus",),
                    tests=("test_corpus_generator_is_deterministic",)),
    )),

    Phase("P3", "producers: test-lift, LLM->IR, graph traversal", PARTIAL, (
        Deliverable("P3.GRAPH", "header + call graph -> IR, with role and contract inference",
                    DONE,
                    modules=("hforge.producers.header_graph",), cli=("propose",),
                    tests=("test_producer_parses_pointer_returning_declarations",
                           "test_role_inference_from_signatures",
                           "test_contract_inference_finds_cstrings_and_length_pairs",
                           "test_proposed_plans_pass_the_static_gates")),
        Deliverable("P3.RANK", "producers compete, gates rank, confidence decides nothing",
                    DONE,
                    modules=("hforge.producers.rank",),
                    tests=("test_ranking_prefers_a_shippable_plan",
                           "test_ranking_prefers_a_higher_kill_rate",
                           "test_ranking_is_deterministic_under_ties")),
        Deliverable("P3.REAL",
                    "the producer works on REAL headers, not just well-formed ones", DONE,
                    modules=("hforge.producers.header_graph", "hforge.analysis.sinks"),
                    tests=("test_multiline_define_does_not_swallow_the_header",
                           "test_extern_c_brace_does_not_swallow_the_header",
                           "test_typedefd_pointer_handle_is_recognised",
                           "test_string_return_is_never_the_handle",
                           "test_unnamed_parameters_are_accepted",
                           "test_macro_wrapped_return_type_parses",
                           "test_export_macros_and_multiline_params_parse",
                           "test_handle_is_not_paired_as_a_length_delimited_buffer",
                           "test_length_pair_is_still_found_from_types_alone",
                           "test_typedefs_are_shared_across_headers",
                           "test_bsd_style_definitions_are_found",
                           "test_sinks_inside_bsd_style_functions_are_attributed"),
                    note="verified against libmagic (file 5.44, from source: full gate suite "
                         "incl. D2), libyaml and libxml2 (installed libs). Before this the "
                         "producer proposed ZERO plans for all three while reporting no "
                         "error."),
        Deliverable("P3.HONESTY",
                    "a stage that could not run yields NOT_RUN results, never silence", DONE,
                    modules=("hforge.cli",),
                    tests=("test_certificate_is_provisional_when_a_gate_did_not_run",),
                    note="a refused emit produced no dynamic gate results at all, so certify "
                         "printed CERTIFIED off six static gates and propose RANKED THE "
                         "BROKEN PLAN FIRST — failing scored better than working."),
        Deliverable("P3.INLINE",
                    "caller-allocated resources: the caller owns the object and passes its "
                    "address", DONE,
                    modules=("hforge.ir", "hforge.emit.c_libfuzzer",
                             "hforge.producers.header_graph"),
                    tests=("test_caller_allocated_handle_is_found",
                           "test_every_lifecycle_is_planned_not_just_the_biggest",
                           "test_inline_resource_emits_address_of_and_zeroing",
                           "test_inline_resource_tracks_liveness_separately",
                           "test_setter_only_plan_chains_the_call_that_does_the_work",
                           "test_out_parameters_are_never_filled_with_fuzzer_bytes"),
                    note="libyaml, zlib z_stream and most C context-struct APIs never return "
                         "a handle. The IR could not express them, so the producer proposed "
                         "2 shallow plans; it now proposes 21 including the real parser "
                         "lifecycle, verified end to end against installed libyaml."),
        Deliverable("P3.TYPECONF",
                    "S2 blocks fuzzer bytes bound to a pointer the library dereferences",
                    DONE,
                    modules=("hforge.gates.static_gates",), gates=("S2",),
                    tests=("test_struct_pointer_fed_with_bytes_is_blocked",
                           "test_byte_pointers_are_still_allowed"),
                    note="a proposed libyaml harness cast raw input to yaml_document_t*, so "
                         "every crash would have been the harness's own invalid pointer. "
                         "The largest single source of false findings in the literature, "
                         "decidable from the plan with no compiler and no campaign."),
        Deliverable("P3.UNRANKED",
                    "ranking refuses to name a winner when no gate distinguishes the "
                    "candidates", DONE,
                    modules=("hforge.producers.rank",),
                    tests=("test_ranking_refuses_a_winner_with_no_discriminating_evidence",
                           "test_ranking_still_names_a_winner_when_evidence_differs"),
                    note="74 libxml2 plans scored identically and the alphabetically-first "
                         "was printed as 'Selected by gate evidence'. Nothing had been "
                         "selected."),
        Deliverable("P3.PREPROC",
                    "headers are parsed through the real C preprocessor", DONE,
                    modules=("hforge.producers.header_graph",),
                    tests=("test_macro_wrapped_function_name_parses",
                           "test_parenthesised_name_keeps_its_return_type",
                           "test_storage_class_is_not_part_of_the_return_type",
                           "test_typedef_aliases_resolve_to_the_same_handle",
                           "test_struct_definition_typedef_is_not_a_pointer_typedef",
                           "test_camelcase_lifecycle_names_are_recognised"),
                    note="four of eight real libraries (bzlib, png, pcre2, lzma) parsed to "
                         "NOTHING by text alone; all ten now yield plans in ~1s total."),
        Deliverable("P3.ACQUIRE",
                    "all three C handle-acquisition forms: returned, caller-allocated, "
                    "out-parameter", DONE,
                    modules=("hforge.ir", "hforge.emit.c_libfuzzer",
                             "hforge.producers.header_graph", "hforge.gates.static_gates"),
                    tests=("test_caller_allocated_handle_is_found",
                           "test_destructor_is_chosen_by_name_not_only_by_signature"),
                    note="sqlite3_open writes its handle through sqlite3**; verified end to "
                         "end against installed expat, magic, sqlite3, yaml and libxml2."),
        Deliverable("P3.DEPTH",
                    "setup-call variants, so depth is measured rather than assumed", DONE,
                    modules=("hforge.producers.header_graph", "hforge.producers.rank"),
                    tests=("test_setup_variants_are_proposed_not_assumed",
                           "test_ranking_leads_on_measured_depth"),
                    note="libmagic magic_buffer: 36 edges without magic_load, 601 with, "
                         "measured by D8. Ranking now leads on edges because reach is a "
                         "prerequisite for detection."),
        Deliverable("P3.SUITE",
                    "batch: generate many harnesses, gate them all, ship only what reaches",
                    DONE,
                    modules=("hforge.cli",), cli=("batch",),
                    tests=("test_batch_command_is_registered",),
                    note="one buildable folder per surviving plan (harness.c, driver.c, "
                         "runnable build.sh, certificate.json) plus a ranked report; "
                         "--min-edges refuses to ship a harness that never leaves the "
                         "library's error path."),
        Deliverable("P3.SCHEDULE",
                    "the campaign budget is spread across distinct entry points", DONE,
                    modules=("hforge.cli", "hforge.analysis.sinks"),
                    tests=("test_ranking_leads_on_measured_depth",),
                    note="a sqlite run spent 10 of 12 slots on variants of ONE entry point "
                         "and shipped nothing. Scheduling now round-robins across distinct "
                         "entry points. The first replacement signal was a FRACTION of "
                         "input-bound args, which scores sqlite3_errmsg(db) at 1.0 and "
                         "sqlite3_exec(db,sql,NULL,NULL,NULL) at 0.2 — exactly backwards; it "
                         "keys on unbounded input reaching the target instead. This is "
                         "SCHEDULING, not ranking: rank.py still reads gate evidence only "
                         "and C10 enforces it."),
        Deliverable("P2.D2COST",
                    "D2 is affordable: mutant objects compile once and link many times", DONE,
                    modules=("hforge.gates.dynamic_gates",),
                    tests=("test_d2_blocks_a_harness_that_cannot_find_a_planted_bug",
                           "test_a_capped_evidence_field_is_not_fed_to_a_gate"),
                    note="a mutant changes the TARGET, not the harness, so the same mutant "
                         "object serves every plan. MEASURED on sqlite: 149.9s for the first "
                         "plan's mutants, 1.2s for the second — the object is compiled once "
                         "and relinked. Plus: D2 was being handed D4's CAPPED "
                         "reachable_functions list, so mutants landed in 200 "
                         "alphabetically-first functions and it reported 0/6. With the full "
                         "3,719 it reports 1/6 PASS."),
        Deliverable("P3.EVIDENCE",
                    "evidence is capped and says when it was capped", DONE,
                    modules=("hforge.analysis.sinks",),
                    tests=("test_reachability_from_entry_points",),
                    note="sink_surface returned the full sorted list of reachable functions "
                         "— 3,719 names for sqlite — computed per plan and stored in every "
                         "certificate, producing 22KB artifacts nobody reads. The count is "
                         "exact; the list is capped at 200 and reports how many it dropped."),
        Deliverable("P3.WALK",
                    "the call-graph walk is linear, not quadratic", DONE,
                    modules=("hforge.analysis.sinks",),
                    tests=("test_the_call_graph_walk_visits_each_function_once",),
                    note="`seen` was marked on POP rather than on PUSH, so every caller of a "
                         "shared helper re-enqueued it: O(V*E). 5.6 SECONDS to walk sqlite's "
                         "4,368 functions, 29 minutes to order 524 candidates. Now ~0ms. I "
                         "benchmarked a 40-plan sample that was mostly cache hits and "
                         "reported a 14.6x speedup that was not real."),
        Deliverable("P3.SCALE",
                    "a batch run is dominated by repeated work; do each piece once", DONE,
                    modules=("hforge.gates.dynamic_gates", "hforge.analysis.sinks",
                             "hforge.cli"),
                    tests=("test_sink_map_is_cached_across_plans",
                           "test_unmeasured_plan_cannot_outrank_a_measured_one",
                           "test_unmeasured_edges_render_as_unknown_not_zero"),
                    note="sqlite (243,646 lines) exposed three: the target was recompiled "
                         "per plan, the sink map was rebuilt per plan (52.4s x 262 = 3.8h), "
                         "and the campaign budget was spent in alphabetical order so "
                         "sqlite3_exec was never built. Measurement is now parallel, both "
                         "caches are keyed on their inputs, and candidates are ordered by "
                         "statically-reachable sink surface."),
        Deliverable("P3.DICT",
                    "fuzzing dictionary mined from the target's own string literals", DONE,
                    modules=("hforge.analysis.dictionary",),
                    tests=("test_dictionary_extracts_the_input_vocabulary",
                           "test_dictionary_drops_program_noise",
                           "test_dictionary_renders_libfuzzer_format",
                           "test_d8_records_whether_a_dictionary_was_used"),
                    note="a parser's vocabulary is written down inside the parser: sqlite3.c "
                         "yields AND/OR/BEGIN/COMMIT/WHERE/INTEGER/:memory:. Shipped as "
                         "target.dict beside each harness; its effect is measured by D8 "
                         "rather than assumed. MEASURED on sqlite3_exec: 867 edges without, "
                         "5441 with, same harness and same 20s budget (6.3x)."),
        Deliverable("P3.INTERCEPT",
                    "report WHERE each defect was caught: on the plan, or only after a build",
                    DONE,
                    modules=("hforge.cli",), cli=("batch",),
                    tests=("test_batch_command_is_registered",),
                    note="the axis this engine differs on. QuartetFuzz intercepted 58 "
                         "harness-induced crashes by RUNNING the harness and attributing the "
                         "crash afterwards; on libmagic 100% of our blocking defects "
                         "(2x S2.TYPE_CONFUSION) cost zero compilation and zero campaign "
                         "time. D2 measured for the first time here: 83-100% mutation kill "
                         "on the deep libmagic harnesses."),
        Deliverable("P3.CHAIN",
                    "multi-resource lifecycles: a resource whose constructor needs another "
                    "resource", DONE,
                    modules=("hforge.producers.header_graph", "hforge.emit.c_libfuzzer"),
                    tests=("test_a_consumer_needing_two_resources_gets_both",
                           "test_resources_are_destroyed_innermost_first",
                           "test_a_creation_verb_need_not_be_called_create",
                           "test_finalize_is_recognised_as_a_destructor",
                           "test_an_accessor_is_not_chosen_as_a_constructor",
                           "test_generated_resource_ids_are_not_doubled",
                           "test_the_deepest_call_gets_the_fuzzer_bytes",
                           "test_a_length_parameter_is_bound_to_its_buffer_not_to_zero",
                           "test_a_filename_parameter_is_never_fed_fuzzer_bytes",
                           "test_a_chain_that_drives_nothing_is_not_proposed",
                           "test_a_partial_chain_is_refused_rather_than_half_built"),
                    note="the real sqlite surface is prepare/bind/step/finalize, where a "
                         "statement cannot exist without a connection. Modelling ONE handle "
                         "per plan meant every statement API got a null statement, so the "
                         "harness crashed on valid input and D3 refused it: the deepest part "
                         "of the library was unreachable by construction. sqlite now yields "
                         "695 plans of which 47 are chains, nesting correctly and destroying "
                         "innermost-first. Three separate causes, each silent: producers were "
                         "gated on init-ish NAMES so sqlite3_prepare_v2 was invisible; "
                         "sqlite3_finalize matched no destructor pattern so every chain "
                         "leaked; and sqlite3_context_db_handle was taken as the connection's "
                         "constructor because the returned-pointer branch used the first "
                         "match rather than ranking. A chain that cannot be fully resolved is "
                         "REFUSED, not half-built — a partial lifecycle passes the static "
                         "gates and then dereferences null. Structure was not enough: the "
                         "first correct chain was still INERT. Slices were allocated "
                         "first-come-first-served, so sqlite3_open's FILENAME took the whole "
                         "input and prepare's SQL stayed literal 0; and the length parameter "
                         "beside it stayed 0, which tells sqlite to read zero bytes of SQL. "
                         "Both calls return OK and produce no statement, so the guarded "
                         "consumer never fires and every gate stays green. MEASURED on the "
                         "sqlite amalgamation, same harness, same 25s: 619 features and a "
                         "corpus that never grew past 2 entries in 800K executions, against "
                         "1313 features and 324 entries once the bytes and the length landed "
                         "where they belong. A path-like parameter is now never fuzzed: "
                         "besides wasting the budget, a harness opening an attacker-named "
                         "file writes arbitrary paths in its working directory."),
        Deliverable("P2.D9D11",
                    "D9 and D11 actually run: both existed and had never once executed",
                    DONE,
                    modules=("hforge.gates.dynamic_gates", "hforge.cli",
                             "hforge.toolchain"),
                    gates=("D9", "D11"), cli=("batch",),
                    tests=("test_a_stack_overflow_is_attributed_not_abstained_on",
                           "test_a_global_overflow_is_attributed",
                           "test_a_harness_owned_stack_buffer_is_ours",
                           "test_the_campaign_hands_its_sanitizer_report_to_the_attributing_gate",
                           "test_the_libfuzzer_probe_is_cached_and_a_timeout_is_not_a_"
                           "missing_runtime"),
                    note="`run_dynamic_gates` took `report` and `sibling_plans` and NOTHING "
                         "in the codebase ever passed either, so D9 reported NOT_RUN 'no "
                         "sanitizer report to attribute' and D11 'only 1 buildable plan' on "
                         "every certificate ever written. D8 is the only thing that produces "
                         "a report and now surfaces it; batch is where siblings exist and "
                         "now groups by entry point. D11 was not merely unwired: the "
                         "scheduling policy that spreads budget across DISTINCT entry points "
                         "GUARANTEED it could never fire, so one campaign slot is now "
                         "reserved for a second variant. Running them found three further "
                         "defects, each invisible while the gates were dead: D9 abstained on "
                         "every STACK and GLOBAL overflow because it only parsed heap "
                         "allocation stacks; the libFuzzer probe recompiled per plan and "
                         "timed out under parallel builds, whereupon D8 blamed the HOST for "
                         "lacking a runtime it had; and `const void *z` was bound as an "
                         "out-parameter, emitting `void hf_out_... = {0};` — not valid C. "
                         "That last plan SHIPPED and was named WINNER off six static gates "
                         "with D1/D2/D3/D5/D6/D8 all reading 'the binary was not built': "
                         "P3.HONESTY caught that failure arriving by the other road, emit "
                         "REFUSING, and nothing watched for emit succeeding and the C not "
                         "compiling. VERIFIED end to end on a small library with a planted "
                         "stack overflow: D9 'library, tiny.c:23, stack' and D11 58/58 "
                         "agreement across two producers."),
        Deliverable("P3.DEEPRUN",
                    "a deep run on a large target, and the five defects it exposed", DONE,
                    modules=("hforge.producers.header_graph", "hforge.cli"),
                    tests=("test_an_opaque_type_is_never_a_caller_allocated_handle",
                           "test_a_nested_struct_body_is_still_a_complete_type",
                           "test_a_struct_body_is_read_from_source_not_from_statements",
                           "test_a_handle_out_parameter_is_never_bound_to_null",
                           "test_an_optional_out_parameter_may_still_be_null",
                           "test_a_setup_call_that_returns_a_handle_is_not_used_as_setup",
                           "test_a_handle_with_no_constructor_is_refused",
                           "test_a_plan_that_never_compiled_is_not_measured"),
                    note="a full batch on the sqlite amalgamation shipped ZERO harnesses and "
                         "every measured plan reached 0 edges. Five defects, each of which "
                         "passed all six static gates and cost a full build and a 45s "
                         "campaign before D3 caught it. (1) A `T **` out-parameter where T "
                         "is a handle the library MAKES was bound to NULL: "
                         "sqlite3_prepare(db, sql, n, NULL, NULL) SEGVs on every input, and "
                         "this one shape took 14 of 14 measurement slots. The rule that "
                         "produced it is right for `char **errmsg`, which sqlite documents "
                         "as optional. (2) The same misbinding one level along, with "
                         "sqlite3_prepare inserted as a SETUP call. (3) sqlite3_blob has no "
                         "recognised constructor — sqlite3_blob_open returns int and writes "
                         "through `sqlite3_blob **` — so plans were emitted with no create "
                         "op and a NULL handle. (4) An OPAQUE type was proposed as a "
                         "caller-allocated handle: `typedef struct sqlite3_stmt "
                         "sqlite3_stmt;` has unknown size, so the emitted `sqlite3_stmt "
                         "hf_r_h;` is not valid C — and three such harnesses SHIPPED with "
                         "certificates. Complete types are now found by brace COUNTING over "
                         "raw source; a regex handling one nesting level called "
                         "yaml_parser_s incomplete while still matching sqlite's flat "
                         "typedefs, so it looked correct. (5) `measured` accepted any "
                         "non-NOT_RUN gate starting with D, and D4 is static reachability "
                         "needing no binary — so uncompilable plans read as measured. It "
                         "now names the gates that require a build. Net: 708 -> 629 plans, "
                         "79 of which could never have worked."),
        Deliverable("P3.FEEDER",
                    "input delivered by a setter, for targets that take no buffer", DONE,
                    modules=("hforge.producers.header_graph",),
                    tests=("test_input_arrives_through_a_setter_when_the_target_takes_none",
                           "test_the_feeder_receives_the_fuzzer_bytes_and_their_length",
                           "test_a_complete_out_struct_is_allocated_and_destroyed",
                           "test_fuzzer_bytes_are_never_bound_to_a_structured_pointer",
                           "test_uint8_counts_as_a_byte_type"),
                    note="found by running QuartetFuzz's own benchmark. A whole class our "
                         "sqlite work could not expose, because sqlite passes input as a "
                         "PARAMETER: `yaml_parser_load(parser, document)` carries no buffer, "
                         "and the bytes arrive earlier through "
                         "yaml_parser_set_input_string. With no way to express that, 64 of "
                         "70 libyaml plans were blocked and NONE reached the gold entry "
                         "point — either bytes went to the OUT parameter, which S2 correctly "
                         "refused, or the setter was called and the parser never was. Three "
                         "parts: a feeder search when a plan would otherwise be discarded "
                         "for having nothing the fuzzer drives; caller-allocated OUT structs "
                         "(yaml_parser_load ASSERTS document non-NULL, and it must be "
                         "destroyed or LeakSanitizer reports every input — the libcue "
                         "mistake); and bytes bound only to byte-carrying pointers, so the "
                         "producer stops making the mistake S2 exists to catch. MEASURED "
                         "against the gold OSS-Fuzz harness on libyaml/libyaml_loader_fuzzer, "
                         "600s libFuzzer, empty corpus, llvm-cov: 77.4% lines vs gold 77.7%, "
                         "71.3% branches vs 66.4%, and vs QuartetFuzz's own published run on "
                         "the same case, 73.89% lines / 57.74% branches. `uint8_t` was not "
                         "in the byte-type set, which our own tests caught and I did not."),
        Deliverable("P3.REUSE_VERB",
                    "a reuse verb does not win the destructor slot", DONE,
                    modules=("hforge.producers.header_graph",),
                    tests=("test_a_reuse_verb_does_not_win_the_destructor_slot",
                           "test_a_reuse_verb_is_still_used_when_a_library_offers_nothing_else"),
                    note="the THIRD defect libde265 exposed before it ran an execution. "
                         "`de265_reset(ctx)` clears the decoder's state so the SAME context "
                         "can decode another stream — the context is still alive and still "
                         "has to be freed — but it returns void, takes only the handle, and "
                         "ends in a verb _FINI_ISH matches, so it ranked as the best "
                         "destructor and beat `de265_free_decoder`, which returns a "
                         "de265_error status and therefore only matched the weaker "
                         "any-position pattern. The harness would have leaked the whole "
                         "decoder context on EVERY input, and under LeakSanitizer every "
                         "finding would be the harness's own. Same shape as expat's "
                         "XML_DefaultCurrent and Brotli's HasMoreOutput, a third time "
                         "through a different door. _FINI_ISH is deliberately left ALONE: "
                         "it is load-bearing in role inference in five other places and "
                         "narrowing it there would change targets that are currently "
                         "correct. A new _REUSE_ISH demotes reset/clear/rewind/reinit in "
                         "the destroyer ranking only, and only below a real candidate — a "
                         "library whose only teardown call is _reset still gets it, which "
                         "the second test pins."),
        Deliverable("P3.CXX_LINKAGE",
                    "a C harness keeps an unmangled entry point under a C++ compiler", DONE,
                    modules=("hforge.emit.c_libfuzzer",),
                    tests=("test_a_c_harness_still_exports_an_unmangled_entry_point_under_cxx",),
                    note="found by ADDING A TARGET, before that target ever ran. libde265 is "
                         "C++ behind an extern \"C\" API — the common codec shape — so the C "
                         "producer reads its header and the C backend emits the harness, but "
                         "the build must use clang++ to link against C++ objects. The C "
                         "backend emitted a bare `int LLVMFuzzerTestOneInput`, which clang++ "
                         "MANGLES. libFuzzer looks up the unmangled symbol, does not find it, "
                         "and the campaign then compiles, links, reports executions and NEVER "
                         "CALLS THE HARNESS — a silent zero that would have read as 'the "
                         "engine cannot do C++'. The C++ backend has carried the guard since "
                         "it was written; the C backend never had it because no case "
                         "exercised the path until now. Guarded with #ifdef __cplusplus in "
                         "both the harness and the replay driver, so a C build is unchanged."),
        Deliverable("P3.UNCREATABLE_HANDLE",
                    "a handle nothing can construct does not refuse the constructor", DONE,
                    modules=("hforge.producers.header_graph",),
                    tests=("test_a_handle_nothing_can_construct_does_not_refuse_the_constructor",),
                    note="jbig2dec parsed PERFECTLY — eight declarations, right types, right "
                         "handle, right roles — and proposed zero plans. "
                         "`jbig2_ctx_new_imp(Jbig2Allocator *, ..., Jbig2GlobalCtx *, ...)` "
                         "was refused by the _unsatisfied_handle guard, because both pointer "
                         "parameters count as returned handles — and they count ONLY because "
                         "a destructor hands one back: `Jbig2Allocator "
                         "*jbig2_ctx_free(Jbig2Ctx *)`. Nothing in the library constructs "
                         "either type. The guard is right for sqlite3_blob_open, where a "
                         "NULL connection crashes on every valid input and 13 of 14 measured "
                         "plans were that shape; it is wrong when NULL is the only call "
                         "anyone could make, which jbig2dec documents. The test is now 'can "
                         "this library create one', not 'is this a handle'."),
        Deliverable("P3.TYPEDEF_CALLBACK",
                    "a callback behind a typedef is still a callback", DONE,
                    modules=("hforge.producers.header_graph",),
                    tests=("test_a_typedef_hides_a_callback_and_it_still_binds_null",),
                    note="`typedef void (*Jbig2ErrorCallback)(...)` then `Jbig2ErrorCallback "
                         "error_callback` — no star at the use site, so the inline-callback "
                         "check never fired and the type read as unmappable. Binding fuzzer "
                         "bytes to a function pointer has the library call an address made "
                         "of input, which is arbitrary control flow and every crash the "
                         "harness's own. Function-pointer typedefs are now recorded in the "
                         "pointer map under a sentinel pointee that matches no handle, so "
                         "they travel through hkey() with everything else and bind NULL — "
                         "the same treatment sqlite3_exec's inline callback already got."),
        Deliverable("P3.NAMED_CONSTANT",
                    "a version parameter takes the constant it is named after", DONE,
                    modules=("hforge.producers.header_graph",),
                    tests=("test_a_version_parameter_takes_the_constant_it_is_named_after",),
                    note="jbig2dec's real constructor is a MACRO: jbig2_ctx_new(...) expands "
                         "to jbig2_ctx_new_imp(..., JBIG2_VERSION_MAJOR, "
                         "JBIG2_VERSION_MINOR). A producer reading declarations sees only "
                         "the _imp function and binds its trailing ints to 0 — and "
                         "jbig2_ctx_new_imp RETURNS NULL when they do not match the library "
                         "it was compiled against. The handle is NULL, every guarded call is "
                         "skipped, and a 600-second campaign touches nothing while every "
                         "gate that reads the plan passes. The parameter is named "
                         "`jbig2_version_minor` and the header defines JBIG2_VERSION_MINOR "
                         "as 20, so the value is READ FROM THE HEADER rather than guessed. "
                         "Object-like integer macros are collected from the raw text before "
                         "preprocessing, since making them disappear is what the "
                         "preprocessor is for."),
        Deliverable("P3.INLINE_BODY_DECL",
                    "a declaration after a static inline body is not discarded", DONE,
                    modules=("hforge.producers.header_graph",),
                    tests=("test_a_declaration_after_an_inline_body_is_not_discarded",),
                    note="jansson.h defines json_incref as a static inline and declares "
                         "`void json_delete(json_t *json);` on the next line. Statements "
                         "split on `;`, so the declaration arrives carrying the inline "
                         "body's closing brace and a check for `{` threw the whole thing "
                         "away. jansson then had a handle it must free and NO DESTRUCTOR, "
                         "every plan using its entry point was dropped for leaking, and the "
                         "benchmark reported NO PLAN for a library that parsed fine. "
                         "Header-only helpers are everywhere. The brace strip must run "
                         "BEFORE the definition check because the statement carries both "
                         "braces — the version that ran it after did not work, which is why "
                         "the test asserts json_delete IS parsed and json_incref is NOT."),
        Deliverable("P3.RESOLVED_TYPE",
                    "the IR records what a typedef resolves to, so a gate can judge it",
                    DONE,
                    modules=("hforge.ir", "hforge.gates.static_gates"),
                    tests=("test_the_ir_records_what_a_typedef_resolves_to",),
                    note="S2 keeps its own list of byte spellings ON PURPOSE — a gate must "
                         "not depend on the thing it judges — and so it could not know that "
                         "leptonica's `l_uint8` is `unsigned char`. It saw a pointer to an "
                         "unknown structured type, called binding fuzzer bytes to it type "
                         "confusion, and refused the ONLY correct harness for pixReadMem. "
                         "TypeRef now carries `resolved`, filled by the producer when a "
                         "typedef changed the answer, and the gate reads that. Independence "
                         "is preserved in the right way: the gate judges a fact RECORDED IN "
                         "THE ARTIFACT, printed and diffable in the certificate, rather than "
                         "a claim handed to it by the producer."),
        Deliverable("P3.CROSS_HEADER_ALIASES",
                    "collect scalar aliases across the whole translation unit", DONE,
                    modules=("hforge.producers.header_graph",),
                    tests=("test_a_librarys_own_byte_spelling_is_read_not_guessed",),
                    note="was PLANNED an hour ago and is now shipped, plus the root cause "
                         "underneath it. The per-header filter in _preprocess is right for "
                         "declarations — without it the producer proposes harnesses for "
                         "stdio — and wrong for TYPEDEFS, because what a type MEANS is not "
                         "local to a file. header_byte_aliases now preprocesses with the "
                         "filter off. THE DEEPER CAUSE was that _preprocess returned None "
                         "for leptonica at all: allheaders.h includes alltypes.h which "
                         "includes endianness.h, a file leptonica's configure GENERATES. "
                         "Five steps from a missing generated header to a gate verdict about "
                         "something else: no endianness.h -> no preprocessing -> raw text -> "
                         "environ.h's `typedef unsigned char l_uint8` unseen -> pixReadMem "
                         "does not look like it takes bytes -> the producer hunts for a "
                         "setter and picks boxaPlotSides, a PLOTTING function -> S1 and S2 "
                         "refuse it. benchmarks/targets/leptonica.sh writes the header, and "
                         "the case now yields two gate-passing plans reading "
                         "pixReadMem -> pixDestroy."),
        Deliverable("P3.BYTE_ALIAS",
                    "a library's own byte spelling is read from the header, not guessed",
                    DONE,
                    modules=("hforge.producers.header_graph",),
                    tests=("test_a_librarys_own_byte_spelling_is_read_not_guessed",
                           "test_an_opaque_struct_typedef_is_not_followed"),
                    note="BYTE_BASES was a list of SPELLINGS that grew once per library — "
                         "Bytef for zlib, guchar for glib, xmlChar for libxml2, png_byte for "
                         "libpng. leptonica spells a byte `l_uint8`, so `pixReadMem(const "
                         "l_uint8 *, size_t)` did not look like it takes bytes at all: the "
                         "producer concluded the entry point had no input, went looking for a "
                         "SETTER to feed the handle, and chose `boxaPlotSides` — a plotting "
                         "function. S1 and S2 refused the result, correctly, which is why "
                         "run-015 reported 'all plans refused by a static gate'. Scalar "
                         "typedefs are now followed, so the header's own `typedef unsigned "
                         "char l_uint8;` answers the question. GUARD, learned the hard way: "
                         "the first version resolved EVERY scalar typedef, which put "
                         "`typedef struct _Jbig2Ctx Jbig2Ctx;` in the table and made handles "
                         "stop comparing equal to themselves — nine tests failed. Only "
                         "aliases bottoming out in a byte type are kept."),
        Deliverable("P3.CROSS_HEADER_ALIASES",
                    "collect scalar aliases across headers, as pointer typedefs already are",
                    PLANNED,
                    note="P3.BYTE_ALIAS is correct and INERT for leptonica, which is the "
                         "target that motivated it. `typedef unsigned char l_uint8;` lives in "
                         "environ.h and the case parses allheaders.h; the alias table is "
                         "filled per FILE. header_typedefs() already solves exactly this for "
                         "POINTER typedefs, and the comment there says why: libxml2 declares "
                         "xmlReadMemory in parser.h and typedefs xmlDocPtr in tree.h. "
                         "VERIFIED, not assumed: _preprocess returns None for leptonica both "
                         "on the host AND in the benchmark container, so the include is never "
                         "inlined and the fallback reads allheaders.h as raw text. Two things "
                         "to do and they are separable — find out why the preprocessor "
                         "declines this header, and collect scalar aliases across all of a "
                         "target's headers the way pointer typedefs already are."),
        Deliverable("P3.CAPS_TYPE",
                    "an all-caps type is not an export macro", DONE,
                    modules=("hforge.producers.header_graph",),
                    tests=("test_an_all_caps_type_is_not_mistaken_for_an_export_macro",),
                    note="found by pointing the engine at leptonica, Tier B of the "
                         "attack-surface map and the OCR stack under tesseract. "
                         "`LEPT_DLL extern PIX * pixReadMem(...)`: LEPT_DLL is an export "
                         "macro and PIX is the RETURN TYPE, and case alone cannot tell them "
                         "apart. Stripping both left the return type as a bare `*`, which "
                         "has no identifier, so the declaration was dropped — and with it "
                         "EVERY pointer-returning function in the library. Measured effect: "
                         "1482 declarations parsed, no pixReadMem, and the handle "
                         "mis-inferred as `l_uint8 *` from a parameter, so the benchmark "
                         "reported NO PLAN for the gold target. After the fix: 2747 "
                         "declarations, handle `PIX *`, and plans that call it. A decoration "
                         "macro precedes the type, so when nothing else survives the last "
                         "uppercase token is the one that has to be the type."),
        Deliverable("P3.TRAILING_ATTR",
                    "an attribute macro after the parameter list is not the declaration",
                    DONE,
                    modules=("hforge.producers.header_graph",),
                    tests=("test_an_attribute_macro_after_the_parameter_list_is_not_the_declaration",
                           "test_a_macro_wrapping_the_name_is_still_stripped"),
                    note="jansson declares its entry point as `json_t *json_loadb(...) "
                         "JANSSON_ATTRS((warn_unused_result));`. _split_call scans BACKWARDS "
                         "for the parameter list — correctly, because a parameter may be a "
                         "function pointer — and so found JANSSON_ATTRS's parentheses "
                         "instead. The declaration parsed with name='JANSSON_ATTRS' and "
                         "json_loadb was never seen, which is why the benchmark reported NO "
                         "PLAN. __attribute__((...)), __declspec(...), WARN_UNUSED_RESULT "
                         "and every project's own spelling have this shape. The guard that "
                         "makes the fix safe: the text BEFORE the suffix must itself end in "
                         "`)`, which is what keeps `BZ_API(BZ2_bzCompressInit)(bz_stream *)` "
                         "and png's parenthesised name intact — there the macro wraps the "
                         "NAME and the real parameter list is genuinely last."),
        Deliverable("P3.NOMINAL",
                    "opaque `void *` typedefs are distinct types, not all `void`", DONE,
                    modules=("hforge.producers.header_graph",),
                    tests=("test_two_void_star_typedefs_are_not_the_same_type",
                           "test_a_returned_handle_is_closed_by_the_right_destructor",
                           "test_a_destroy_verb_mid_name_is_recognised",
                           "test_a_hungarian_prefixed_length_is_still_a_length",
                           "test_the_length_is_bound_when_only_the_name_says_so",
                           "test_an_explicitly_named_seed_directory_is_trusted"),
                    note="found by pointing the engine at an UNFUZZED target — lcms2, Tier B "
                         "of the native attack-surface map, in the JDK, Skia, Pillow and "
                         "libvips. Five defects the QuartetFuzz benchmark never exposed, "
                         "because those libraries do not spell things this way. (1) "
                         "`cmsHPROFILE` and `cmsHANDLE` are both `typedef void *`; resolving "
                         "the pointee made them ONE type, so a colour profile was paired "
                         "with cmsDictFree — a dictionary's destructor. A void* typedef is "
                         "NOMINAL. Fixing it surfaced six distinct handles where we saw one "
                         "and took proposals from 264 to 372. (2) `cmsCloseProfile` matched "
                         "no destructor pattern because the verb sits mid-name. (3) The "
                         "owned-return cleanup kept a PRIVATE COPY of that lookup with the "
                         "same bug, so fixing the shared one was not enough. (4) `dwSize` "
                         "was not recognised as a length — `_LENISH` is start-anchored and "
                         "Hungarian notation is everywhere in older C — so the profile "
                         "length was bound to 0, lcms2 was told the profile is zero bytes, "
                         "and 21 MILLION executions reached 1.95%. (5) The seed miner "
                         "ignored `testbed/` because only directories whose names look like "
                         "test data were trusted, even when the operator names one "
                         "explicitly. MEASURED: lcms2 0.79% -> 5.14% with a correct harness "
                         "(cmsOpenProfileFromMem -> cmsCloseProfile). There is no gold "
                         "figure for an unfuzzed target, so the claim is that the harness is "
                         "right, not that the number is good."),
        Deliverable("P3.INITORDER",
                    "caller-owned storage is initialised after the input is assigned", DONE,
                    modules=("hforge.emit.c_libfuzzer",),
                    tests=("test_scratch_is_initialised_after_the_input_is_assigned",),
                    note="the largest single defect this project has had, and it hid an "
                         "entire capability. Scratch was initialised WHERE IT WAS DECLARED, "
                         "but a slice's pointer and length are assigned later in the body — "
                         "so `const uint8_t *cur = hf_s_input;` ran while hf_s_input was "
                         "still NULL and available_in was still 0. EVERY streaming harness "
                         "we emitted decoded a null pointer of length zero. libFuzzer's own "
                         "log said so and I had not read it: 44 valid brotli streams in, "
                         "`corp: 1/1b` out, coverage frozen at 42 edges. No corpus would "
                         "have revealed it, because the harness could not read its input at "
                         "all. I had attributed the same symptom to 'compression formats "
                         "need valid seeds', which fit the data and was false — the seeds "
                         "changed nothing and the ordering changed everything. MEASURED: "
                         "brotli 6.32% -> 84.42%, zlib 11.43% -> 53.93% with ZERO seeds, "
                         "both past the human OSS-Fuzz harness."),
        Deliverable("P3.MODE",
                    "mode-selecting scalars are driven by the fuzzer, not pinned to 0", DONE,
                    modules=("hforge.producers.header_graph",),
                    tests=("test_a_token_api_is_driven_in_a_loop",),
                    note="`ZopfliDeflate(..., int btype, ...)` selects stored, fixed-Huffman "
                         "or dynamic-Huffman blocks — three entirely different code paths. "
                         "Pinned at 0 the harness only ever exercised stored blocks: 3.04% "
                         "against a gold harness at 85.7%. A bounded byte consumed before "
                         "the remainder, so the fuzzer picks the mode and the input still "
                         "drives the parse. MEASURED: 3.04% -> 84.85% lines, 91.75% "
                         "functions — ahead of QuartetFuzz's 80.06%. Deliberately keyed on "
                         "NAMES (btype, mode, level, format, flags): driving an arbitrary "
                         "integer from fuzzer input violates API contracts, and a contract "
                         "violation is a crash the harness owns."),
        Deliverable("P3.LOOP",
                    "drive the target until the library stops, bounded", DONE,
                    modules=("hforge.ir", "hforge.emit.c_libfuzzer",
                             "hforge.producers.header_graph"),
                    tests=("test_a_token_api_is_driven_in_a_loop",
                           "test_the_loop_is_bounded",
                           "test_per_iteration_cleanup_is_inside_the_loop",
                           "test_the_loop_stops_when_the_library_stops",
                           "test_a_const_handle_is_never_a_destructor"),
                    note="the single largest coverage gap measured against the gold OSS-Fuzz "
                         "harnesses, and it was one missing construct rather than five "
                         "separate problems. Every gold harness for a token, event or "
                         "streaming API repeats the call; ours called once and threw the "
                         "parser away. The evidence was in the execution counts, not in "
                         "guesswork: 77 MILLION executions for 9.6% of libyaml's scanner "
                         "against gold's 70.6%, and 90 million for 39.4% of yajl. MEASURED "
                         "after: scanner 9.60% -> 46.15% and loader 77.47% -> 77.77% in a "
                         "FRACTION of the budget — the loader now ahead of the human harness "
                         "on both lines (77.77 vs 77.7) and branches (70.65 vs 66.4). Two "
                         "shapes repeat: a call that fills a caller-allocated struct, and "
                         "one that advances caller-owned cursors. Bounded at 64, because an "
                         "unbounded loop steered by fuzzer input is a hang and a hang looks "
                         "like a finding until someone checks. Per-iteration cleanup is "
                         "emitted INSIDE the loop or the harness leaks a token per iteration "
                         "— its own bug, reported on every input. Alongside it: a CONST "
                         "handle can never be a destructor, which is why "
                         "BrotliDecoderHasMoreOutput was emitted as brotli's destroy op and "
                         "the decoder state leaked (0.00% -> 6.32%)."),
        Deliverable("P3.SCRATCH",
                    "caller-owned buffers: streaming and free-function entry points", DONE,
                    modules=("hforge.ir", "hforge.emit.c_libfuzzer",
                             "hforge.producers.header_graph", "hforge.gates.static_gates"),
                    tests=("test_scratch_round_trips_through_the_ir",
                           "test_a_free_function_entry_point_gets_a_plan",
                           "test_an_input_length_by_address_is_bound_not_zeroed",
                           "test_a_library_allocated_output_pointer_starts_null_and_is_freed",
                           "test_a_config_struct_is_initialised_before_use",
                           "test_a_void_initialiser_is_not_cast_to_int",
                           "test_complete_types_are_unioned_across_headers",
                           "test_a_subdirectory_header_is_included_by_its_relative_path"),
                    note="the last structural gap, found by running QuartetFuzz's benchmark. "
                         "A library that hands you buffers rather than taking them needs "
                         "storage the HARNESS owns, and the IR could not express any of it — "
                         "so uncompress2, ZopfliDeflate and BrotliDecoderDecompressStream got "
                         "every non-buffer parameter bound to 0, and zlib and zopfli produced "
                         "NO PLAN AT ALL against QuartetFuzz at 51.74% and 80.06%. New: "
                         "Scratch (bytes/size/ptr) in the IR, a free-function producer pass, "
                         "config structs initialised by a helper, and the distinction between "
                         "a CURSOR into a caller buffer (brotli's next_out, paired with "
                         "available_out) and a pointer the LIBRARY allocates and the caller "
                         "frees (zopfli's out, 'must be freed after use') — guessing the "
                         "second wrong is fatal, because the library reallocs storage it "
                         "never malloc'd. Six smaller defects fell out: `Bytef` was not a "
                         "byte type; complete types were read from the FIRST header only, so "
                         "a config struct declared in a second header was invisible; "
                         "`ZopfliInitOptions` matched no init pattern because the verb sits "
                         "mid-name; a void initialiser was cast to int and would not compile; "
                         "a subdirectory header was included by basename, breaking every "
                         "library that namespaces its headers; and the static gates refused "
                         "the new vocabulary, which is fail-closed working as designed."),
        Deliverable("P3.FREEFUNC",
                    "entry points with no handle at all (zlib compress2/uncompress2)",
                    DONE, modules=("hforge.producers.header_graph",),
                    tests=("test_a_free_function_entry_point_gets_a_plan",),
                    note="the second gap the benchmark exposed. Our producer is organised "
                         "entirely around lifecycles, so for zlib it proposes only gz* plans "
                         "— gzFile is the only handle it recognises — and BOTH zlib gold "
                         "cases are handle-free. `uncompress2(Bytef *dest, uLongf *destLen, "
                         "const Bytef *source, uLong *sourceLen)` also needs something the "
                         "IR cannot express: a caller-allocated SCRATCH OUTPUT buffer with "
                         "an in/out size. Recorded as a gap rather than rushed."),
        Deliverable("P3.ERROR_ACCESSOR",
                    "the harness asks the library why it failed, and frees the answer", DONE,
                    modules=("hforge.producers.header_graph",),
                    tests=("test_the_harness_asks_the_library_why_it_failed",
                           "test_the_error_string_is_freed_by_its_own_pair",
                           "test_an_error_accessor_with_no_freer_is_not_called_at_all",
                           "test_a_verbose_flag_is_not_bound_to_the_input_length"),
                    note="MEASURED AND IT WORKS: yajl 65.12 -> 72.80, which is 1.05x gold "
                         "(69.1) where it had been 0.94x — the case flips from this suite's "
                         "only loss against a hand-written harness to a win, and the "
                         "~100 lines of error rendering are now reached. Still behind the "
                         "cited QuartetFuzz 79.87 on this case. It took three runs and two "
                         "wrong diagnoses to get here. CORRECTED TWICE, BOTH TIMES BY MEASUREMENT. The real cause was a "
                         "LOST POINTER: the owned return was given the type hkey() "
                         "resolves, and hkey() resolves to a BASE type, so `unsigned char *` "
                         "was declared `unsigned char`. The returned pointer was truncated "
                         "into one byte and the paired free segfaulted. The handle escaped "
                         "only because `yajl_handle` is a typedef carrying its own star. "
                         "The C compiler warned (incompatible pointer-to-integer conversion) "
                         "and the build succeeded anyway — see P3.BENCH_NO_DYNAMIC_GATES and "
                         "P3.WARNINGS_ARE_EVIDENCE. My FIRST diagnosis blamed the verbose "
                         "flag and a genuine stack overflow in yajl_render_error_string; "
                         "that code is real but it was not this crash, and re-measuring with "
                         "verbose=0 returned 0.00% again. Reading the emitted declaration "
                         "found it in a minute. verbose stays 0 on its own merits. "
                         "EARLIER NOTE FOLLOWS. The first version of this entry "
                         "claimed the harness was right and said only that the coverage "
                         "effect was unmeasured. Measuring it (run-011) returned 0.00% "
                         "against 65.12% before: the harness SEGV'd on its third execution, "
                         "inside yajl_free_error, because the scalar `verbose` was bound to "
                         "1 and yajl_render_error_string's verbose branch writes up to about "
                         "a hundred bytes into `char text[72]` behind an assert that fires "
                         "after the overflow. I picked 1 so the flag would select the longer "
                         "message and reach more of the renderer — optimising an argument "
                         "for coverage rather than choosing it because the contract allows "
                         "it, which is the instinct this engine exists to refuse. Now 0, "
                         "pinned. The deeper defect is P3.BENCH_NO_DYNAMIC_GATES: D3 would "
                         "have caught this before a 600-second campaign was spent. "
                         "v1 SHIPPED. The plan for yajl now runs alloc -> parse -> "
                         "complete_parse -> get_error(h, 1, data, len) -> free_error -> "
                         "free, all static gates pass, and the emitted C guards the release "
                         "on both the handle and the string. NOT gated on failure, "
                         "deliberately: that needs a new Op field AND a rule for what counts "
                         "as non-OK, and the convention is library-specific (yajl_status_ok "
                         "is 0), so assuming 'non-zero is failure' would be inventing a "
                         "contract. Calling the accessor after a SUCCESSFUL parse is legal "
                         "and still reaches the renderer. The freer is MANDATORY: with no "
                         "matching release the accessor is left out entirely, because half "
                         "the pair leaks on every input and LeakSanitizer would then report "
                         "the harness's own defect as a finding. One bug found by reading "
                         "the emitted output rather than trusting it: `int verbose` was "
                         "bound to length_of(jsonText), because a scalar beside a buffer "
                         "looks like a length until you use the DECLARED "
                         "contract.length_delimited pairing instead of the type. Whether "
                         "this moves 65.12 toward gold's 69.1 is unmeasured as of this "
                         "entry — the claim here is that the harness is right, not that the "
                         "number moved."),
        Deliverable("P3.WARNINGS_ARE_EVIDENCE",
                    "a compiler warning about the harness is a gate signal, not noise",
                    DONE,
                    modules=("hforge.toolchain",),
                    tests=("test_a_pointer_squeezed_into_a_byte_is_refused_before_the_campaign",),
                    note="SHIPPED. toolchain.check_emitted_c compiles the harness ALONE with "
                         "-fsyntax-only and -Werror on four classes that can only mean an "
                         "emitter defect: int-conversion, incompatible-pointer-types, "
                         "implicit-function-declaration, return-type. benchmarks/drive.py "
                         "runs it after emit and REFUSES the plan before building or "
                         "campaigning, writing the diagnostic to emitter-defect.log. "
                         "Compiled ALONE and deliberately not as part of the real build: the "
                         "target's own sources routinely carry warnings of exactly these "
                         "classes, and attributing somebody else's warning to our plan would "
                         "be the same error in the opposite direction. Verified against the "
                         "defect that shipped — it refuses the truncated pointer and passes "
                         "the fix. WHAT IT CATCHES: "
                         "`unsigned char hf_r_err = NULL;` then "
                         "`hf_r_err = yajl_get_error(...)` is an incompatible "
                         "pointer-to-integer conversion. clang says so, the build succeeds, "
                         "nobody reads it, and the campaign spends 600 seconds proving it. "
                         "This is S2.TYPE_CONFUSION — the gate this engine already has — "
                         "occurring at the C level after emission, where no gate looks. Fix: "
                         "compile the harness with -Werror on the conversion classes that "
                         "indicate an emitter defect (int-conversion, "
                         "incompatible-pointer-types, implicit-function-declaration) and "
                         "attribute the failure to the PLAN, not to the target. A warning "
                         "about generated code is evidence about the generator."),
        Deliverable("P3.BENCH_NO_DYNAMIC_GATES",
                    "the benchmark driver runs static gates only", DONE,
                    modules=("hforge.toolchain",),
                    tests=("test_a_pointer_squeezed_into_a_byte_is_refused_before_the_campaign",),
                    note="FIXED. drive.py now runs D1 and D3 after the build and before the "
                         "campaign. D1: the target symbol must be in the binary, because a "
                         "call clang proved dead and deleted leaves a harness that runs and "
                         "reaches nothing, and coverage cannot tell that apart from a hard "
                         "target. D3: a 400-execution run over the mined seeds, because a "
                         "harness that faults on input the library ACCEPTS is reporting its "
                         "own defect. Not the whole gate bank — those build their own binary "
                         "and this one already exists; these two are nearly free once it "
                         "does. VERIFIED AGAINST THE ARTIFACT: the harness that shipped this "
                         "morning, declaring `unsigned char hf_r_err = NULL;`, was rebuilt "
                         "and the smoke test refuses it with exit 1. That defect cost two "
                         "600-second campaigns and three wrong diagnoses; the check costs "
                         "400 executions. A refused plan is now reported as REFUSED with the "
                         "sanitizer's own first line, rather than measured as 0.00% — which "
                         "is the difference between an engine that failed and an engine that "
                         "said why. WHAT IT REPLACED: "
                         "benchmarks/drive.py called run_static_gates and nothing else, so "
                         "every case is built and campaigned on a plan that passed S1-S6 and "
                         "was never checked by D1-D11. The cost is not theoretical: the "
                         "error-accessor harness crashed on its third execution with a "
                         "corrupted stack, D3 (valid input must not crash) exists precisely "
                         "to catch that, and instead the defect consumed a 600-second "
                         "campaign and produced a 0.00% row. A benchmark that bypasses the "
                         "gate bank is measuring a generator, which is the thing this "
                         "project argues is not the bottleneck. Fix: run the dynamic gates "
                         "in drive.py before the campaign and record their verdicts on the "
                         "row, so a refused plan is reported as refused rather than measured "
                         "as zero.'"),
        Deliverable("P3.DRIVE_LOOP",
                    "loop a drive call on its continuation out-parameter", PLANNED,
                    note="libde265's gold harness loops `while (more) { de265_decode(ctx, "
                         "&more); while (img = de265_get_next_picture(ctx)) {} }`. Ours "
                         "calls de265_decode ONCE and never asks for output at all, so one "
                         "step of a multi-frame pipeline is all it gets. Op.repeat exists "
                         "and is what took the libyaml scanner from 9.6% to 70%, but its "
                         "trigger keys off a caller-allocated out-STRUCT or advancing "
                         "cursors, and `int *more` is neither. The shape to recognise: a "
                         "call that fills a scalar out-parameter acting as a keep-going "
                         "flag. Pair it with a drain loop for the output accessor."),
        Deliverable("P3.LOOP_TERMINATION",
                    "the repeat loop's exit condition assumes non-zero means progress",
                    PLANNED,
                    note="READ THE EMITTER, do not trust its comment. c_libfuzzer emits "
                         "`sink += (long)(call); if (!sink) break;` and the comment says "
                         "'stop when the library stops making progress'. Two things are "
                         "wrong with that. (1) `sink` ACCUMULATES, so the test is not on "
                         "this call's result but on the running total — once any iteration "
                         "returns non-zero the loop can never break again and always runs "
                         "the full bound. The real semantics are 'break only if the library "
                         "has never once returned non-zero'. (2) It encodes a CONVENTION: "
                         "non-zero means keep going. That holds for yaml_parser_scan (1 on "
                         "success) and for BrotliDecoderDecompressStream, which are the "
                         "cases that were measured. It is BACKWARDS for every library where "
                         "OK is zero — de265_error DE265_OK is 0, yajl_status_ok is 0 — "
                         "where the loop breaks after the first SUCCESSFUL call. Same "
                         "library-specific convention problem as P3.ERROR_ACCESSOR_GATED, "
                         "and it wants the same answer: read the contract or do not assume. "
                         "NOT fixed here on purpose — changing loop termination moves every "
                         "streaming case's number, and doing that in the middle of a "
                         "benchmark comparison would make the comparison meaningless."),
        Deliverable("P3.ERROR_ACCESSOR_GATED",
                    "run the error accessor only on the failure branch", PLANNED,
                    note="found by measurement, not by reading a header. yajl is the one "
                         "run-009 case behind gold (65.12 vs 69.1, 0.94x), and the deficit "
                         "is almost entirely one file: yajl.c at 45.26% while the lexer is "
                         "at 77%. The uncovered functions are yajl_render_error_string (72 "
                         "lines), yajl_status_to_string, yajl_get_bytes_consumed and "
                         "yajl_get_error itself — roughly a hundred lines reachable ONLY "
                         "after a parse fails and the caller asks why. A fuzzer drives that "
                         "path constantly; our harness never asks. The emitted lifecycle "
                         "(alloc/parse/complete/free) is CORRECT and every gate passes; the "
                         "coverage it misses is coverage no correct lifecycle reaches. "
                         "_finisher_for already models finishers, but it picks queries on "
                         "the SUCCESS path. This is a different shape: an accessor gated on "
                         "the consuming call returning non-OK, paired with a matching free. "
                         "DESIGN, after reading the IR: gating on failure needs a new Op "
                         "field (which op's status, and what counts as non-OK) and the "
                         "'non-OK' convention is library-specific — yajl_status_ok is 0, "
                         "and assuming that everywhere would be inventing a contract. So v1 "
                         "does NOT gate: it relaxes _finisher_for's one-parameter rule to "
                         "allow a finisher taking the handle plus arguments the plan has "
                         "ALREADY bound (the input slice, a constant flag), treats its "
                         "returned pointer as owned, and pairs it with its freer through "
                         "the owned-return cleanup that already exists. Calling "
                         "yajl_get_error after a successful parse is legal and still "
                         "reaches the renderer, so v1 costs no contract violation and no IR "
                         "change. Failure-branch gating is v2, and it needs the Op field. "
                         "The pairing is not optional — without yajl_free_error the harness "
                         "leaks on every failing input and under LeakSanitizer every "
                         "finding would be the harness's own, which is what S1 exists to "
                         "block. So the free comes with it or the plan is refused. "
                         "Evidence: benchmarks/results/logs/run-009/yajl-ruby__json_fuzzer/"),
        Deliverable("P3.OPTION_SETTER",
                    "varargs option setters between create and consume", PLANNED,
                    note="`yajl_config(yajl_handle h, yajl_option opt, ...)` — 19 lines at "
                         "0%, and each option it sets (allow_comments, "
                         "allow_trailing_garbage, allow_multiple_values, "
                         "dont_validate_strings) unlocks lexer and parser paths that are "
                         "dead under the defaults. _CONFIG_INIT models a config STRUCT "
                         "filled before construction, not a (handle, enum, value) setter "
                         "called after it. This one needs care rather than enthusiasm: a "
                         "harness that flips dont_validate_strings is testing a different "
                         "contract, so the honest form is ONE PLAN PER CONFIGURATION, each "
                         "certified separately with its options recorded in the IR — never "
                         "one harness that sets everything."),
        Deliverable("P3.OPS_TABLE",
                    "synthesise a callback table for libraries that take one", PLANNED,
                    note="graphite2 has NO entry point that takes (bytes, len). Every face "
                         "constructor takes a callback table — gr_make_face_with_ops(handle, "
                         "const gr_face_ops*, options), or the deprecated gr_make_face with "
                         "a gr_get_table_fn. A harness must SYNTHESISE a callback that "
                         "serves TTF tables out of the fuzzer buffer. Today S2.TYPE_CONFUSION "
                         "correctly blocks binding fuzzer bytes to a function pointer, so "
                         "the engine refuses graphite2 — and refusing is right, but it is "
                         "not a harness. The shape is common across font and codec "
                         "libraries. We already have the Scratch machinery for a "
                         "caller-owned buffer; the missing half is emitting a fixed static "
                         "function that reads from it. Note the emitted callback must NOT be "
                         "fuzzer-derived: the bytes it SERVES come from input, the code that "
                         "serves them does not."),
        Deliverable("P3.LIFT", "unit tests -> IR (the UTopia insight)", PLANNED),
        Deliverable("P3.LLM", "LLM fleet emitting IR, never C", PLANNED),
    )),

    Phase("PX", "cross-platform hardening: run the same way on every host", DONE, (
        Deliverable("PX.TOOLCHAIN",
                    "host detection, compiler/nm resolution, OS-correct exit classification",
                    DONE,
                    modules=("hforge.toolchain",),
                    tests=("test_windows_crash_is_not_read_as_a_clean_run",
                           "test_posix_signal_number_is_not_a_windows_crash",
                           "test_driver_error_is_distinct_from_a_fault",
                           "test_sanitizer_exit_1_only_counts_when_sanitized",
                           "test_host_maps_to_a_modelled_platform",
                           "test_gates_use_the_shared_toolchain",
                           "test_replay_binary_gets_an_exe_suffix",
                           "test_run_once_delegates_classification"),
                    note="the exit-code check was POSIX-only, so on Windows every crash "
                         "would have read as a clean run and the engine would have certified "
                         "harnesses that detect nothing. VERIFIED on macOS-arm64, "
                         "linux-aarch64-glibc, linux-aarch64-musl and linux-x86_64-glibc; "
                         "Windows semantics are unit-tested but not yet run on Windows."),
        Deliverable("PX.DEVICES",
                    "Android over adb and iOS simulators over simctl: inventory, "
                    "NDK cross-build, push-run, tombstone retrieval", DONE,
                    modules=("hforge.devices",), cli=("devices",),
                    tests=("test_every_device_platform_id_is_modelled",
                           "test_device_functions_degrade_without_hardware",
                           "test_missing_ndk_reports_a_reason_not_a_silent_false",
                           "test_hwasan_downgrades_loudly_not_silently",
                           "test_android_run_classifies_with_linux_semantics")),
        Deliverable("PX.ARTIFACT",
                    "on-device differential: a fault seen only under instrumentation is an "
                    "artifact, not a finding", DONE,
                    modules=("hforge.devices",),
                    tests=("test_instrumented_only_fault_is_an_artifact_not_a_finding",
                           "test_fault_in_both_builds_is_a_real_fault",
                           "test_sanitizer_report_makes_an_instrumented_only_fault_real",
                           "test_missing_baseline_is_stated_not_assumed",
                           "test_artifact_is_not_reportable",
                           "test_hwasan_needs_a_hwasan_system_image_not_just_arm64",
                           "test_build_records_the_detector_it_was_denied"),
                    note="verified adversarially on a live arm64 emulator: a forced HWASan "
                         "build SIGSEGVs on a stock image and is correctly classified "
                         "non-reportable"),
        Deliverable("PX.MATRIX",
                    "reproducible multi-platform verification with cross-variant certificate "
                    "comparison", DONE,
                    modules=("hforge.toolchain",),
                    tests=("test_host_maps_to_a_modelled_platform",),
                    note="scripts/verify-linux.sh runs three Linux variants under docker and "
                         "diffs the gate verdicts; agreement observed across glibc, musl and "
                         "x86_64. Disagreement is reported as the oracle, not as a failure."),
        Deliverable("PX.OPERATOR",
                    "doctor and selftest: what this machine can do, and proof it does it",
                    DONE,
                    modules=("hforge.cli",), cli=("doctor", "selftest"),
                    tests=("test_operator_commands_are_registered",
                           "test_selftest_treats_skip_as_distinct_from_pass")),
    )),

    Phase("T0", "target choice, seeds and input size: the work that decides findings", DONE, (
        Deliverable("T0.TARGETS",
                    "shortlist unfuzzed input-parsing dependencies of shipped programs",
                    DONE,
                    modules=("hforge.targets.ossfuzz",), cli=("targets",),
                    tests=("test_soname_and_project_name_are_normalised_the_same_way",
                           "test_a_known_unfuzzed_parser_is_a_candidate",
                           "test_the_runtime_is_not_a_target",
                           "test_a_non_parser_is_not_shortlisted"),
                    note="CVE-2025-53367 was a 1-click RCE in a DjVu parser shipped by "
                         "default with Evince on millions of systems and never in OSS-Fuzz. "
                         "We had spent ZERO effort on target choice and aimed at saturated "
                         "libraries."),
        Deliverable("T0.PORTABLE",
                    "the shortlist works on every host, not only where ldd exists", DONE,
                    modules=("hforge.targets.ossfuzz",), cli=("targets",),
                    tests=("test_a_library_reduces_to_the_same_stem_on_every_platform",
                           "test_a_script_is_a_skip_not_an_empty_survey",
                           "test_a_modern_image_codec_reads_as_input_parsing",
                           "test_a_closed_vendor_framework_is_excluded_with_a_reason"),
                    note="the module whose whole job is choosing a target worth fuzzing ran "
                         "on Linux only: `ldd` exists nowhere else, so on macOS and Windows "
                         "it returned None and reported 'ldd failed', which reads as a "
                         "broken binary rather than an unsupported host. Now otool -L and "
                         "the PE import table. Three defects came out of running it here: "
                         "stems were reduced only in the ELF spelling, so every Mach-O and "
                         "PE dependency compared as a MISS against the known-fuzzed set; "
                         "libavif was discarded as 'no sign it parses attacker-controlled "
                         "input' while being the most obvious candidate on the host; and "
                         "otool EXITS 0 on a shell script, so `7z` surveyed as a binary with "
                         "zero dependencies — 'nothing unfuzzed here' rather than 'I could "
                         "not read this'."),
        Deliverable("T0.RESOLVE",
                    "a shortlisted library resolves to headers `propose` can consume", DONE,
                    modules=("hforge.targets.ossfuzz",), cli=("targets",),
                    tests=("test_a_header_named_after_its_library_is_never_demoted",
                           "test_a_loose_prefix_does_not_name_the_wrong_library",
                           "test_trailing_digits_are_part_of_a_library_name",
                           "test_kernel_headers_are_never_a_userspace_api",
                           "test_an_abi_decoration_is_stripped_but_a_version_is_not",
                           "test_usrmerge_spellings_are_both_tried"),
                    note="`targets` produced a list of NAMES and stopped, so the operator "
                         "still looked each one up by hand. VERIFIED end to end in Docker on "
                         "a Debian surface: 11 candidates across 10 shipped tools, and the "
                         "command the tool printed for djvulibre — the library this module "
                         "is named after — proposed 110 plans with no manual lookup. "
                         "Resolution asks the PACKAGING SYSTEM first (dpkg -S on the -dev "
                         "symlink, then rpm), because name heuristics produced confident "
                         "wrong answers: pkg-config --cflags-only-I fontconfig returns "
                         "FreeType's include dirs, so the command said 'fuzz fontconfig' and "
                         "handed over a different library; stripping a trailing version "
                         "turned iso9660 into iso and matched the KERNEL's iso_fs.h; and "
                         "magickwand resolved to /usr/include/linux/magic.h. A wrong target "
                         "is worse than no target — the campaign runs, the certificate is "
                         "valid, and it certifies the wrong thing."),
        Deliverable("T0.SEEDS",
                    "mine example inputs from the target's own test data", DONE,
                    modules=("hforge.analysis.seeds",),
                    tests=("test_seeds_come_from_test_data_not_from_source",
                           "test_duplicate_fixtures_are_dropped",
                           "test_oversized_fixtures_are_excluded_and_counted",
                           "test_a_truncated_corpus_says_so",
                           "test_mining_is_deterministic",
                           "test_seed_dirs_travel_on_the_plan"),
                    note="the dictionary tells the fuzzer the format's words; a seed shows "
                         "it a sentence. MEASURED on libmagic: 117 seeds mined from file's "
                         "own tests took magic_buffer_setup from 565 to 634 edges (+12%) in "
                         "the same 20s. Real but far short of the dictionary's 6.3x on "
                         "sqlite — libmagic's setup variant already loads the magic "
                         "database, so much of the code is reachable without seeds."),
        Deliverable("T0.MAXLEN",
                    "propose max_len as measured variants, not a guessed constant", DONE,
                    modules=("hforge.producers.header_graph",),
                    tests=("test_max_len_is_proposed_as_variants_not_guessed",
                           "test_size_variants_cover_the_same_entry_points"),
                    note="libxml2 CVE-2022-40303 needs >2GB; libFuzzer's silent default is "
                         "4096. A defect needing a larger input is not hard to find, it is "
                         "impossible to express."),
    )),

    Phase("TF", "findings: the half the engine was missing", DONE, (
        Deliverable("TF.LADDER",
                    "the exploitability ladder, one oracle per rung", DONE,
                    modules=("hforge.findings.ladder",),
                    tests=("test_asan_confirming_asan_does_not_reach_rung_three",
                           "test_an_independent_oracle_reaches_rung_three",
                           "test_harness_owned_memory_caps_at_rung_two",
                           "test_a_platform_ceiling_downgrades_rather_than_drops",
                           "test_an_unreproducible_fault_stops_at_rung_one"),
                    note="platform.py has cited rung numbers since Phase 1 for a ladder that "
                         "did not exist. Rung 3 requires an oracle INDEPENDENT of the one "
                         "that discovered the fault: ASan confirming ASan is one witness."),
        Deliverable("TF.GATES",
                    "F1-F8: reproduce, minimise, attribute, variant, artifact, novelty, "
                    "rung, exclusions", DONE,
                    modules=("hforge.findings.gates",),
                    tests=("test_the_entry_point_does_not_make_it_harness_owned",
                           "test_harness_allocated_memory_is_still_caught",
                           "test_no_report_means_not_run_not_a_pass",
                           "test_naming_the_discovering_sanitizer_as_independent_is_refused",
                           "test_a_genuinely_different_oracle_is_accepted",
                           "test_every_rung_above_the_one_reached_is_listed_as_unshown"),
                    note="F3 first matched LLVMFuzzerTestOneInput anywhere in the allocation "
                         "stack — a symbol at the bottom of EVERY such stack. It would have "
                         "suppressed every real finding. It now attributes by allocation "
                         "SITE."),
        Deliverable("TF.AUDITOR",
                    "controls over the finding SET: circularity, baseline, grouping, "
                    "capacity, transfer", DONE,
                    modules=("hforge.findings.auditor",),
                    tests=("test_the_auditor_catches_a_circular_confirmation",
                           "test_the_auditor_groups_one_defect_reached_many_ways",
                           "test_the_auditor_will_not_pass_a_baseline_it_never_ran",
                           "test_a_null_harness_matching_the_suite_is_blocking"),
                    note="'the component nobody builds, because it makes your numbers "
                         "worse'. Every control here can only reduce a claim."),
        Deliverable("TF.FPRATE",
                    "our own false-positive rate, measured against constructed ground truth",
                    DONE,
                    modules=("hforge.findings.fprate",), cli=("fprate",),
                    tests=("test_every_constructed_defect_is_a_harness_bug_not_a_library_bug",
                           "test_the_static_gates_intercept_the_known_defect_classes",
                           "test_no_crashes_is_reported_as_unmeasured_not_as_zero",
                           "test_a_defect_that_never_fired_is_no_evidence_either_way",
                           "test_the_rate_states_both_denominators"),
                    note="QuartetFuzz reports 4.8%; we had never measured the equivalent, "
                         "which made every comparison we drew an argument from architecture "
                         "rather than a result. Ground truth is CONSTRUCTED rather than "
                         "adjudicated: five plans each carrying one harness bug from the "
                         "literature's defect classes, so every crash is false by "
                         "construction and there is nothing to argue about. MEASURED on the "
                         "sqlite amalgamation: 5/5 intercepted by a static gate before any "
                         "compiler ran, and 0 of 8 crashes from those same plans — force-"
                         "built past their own verdict — reached rung 3. The cap is a "
                         "judgement and not an absence: F1 reproduced each crash and F3 "
                         "attributed it, 'the offending access is the HARNESS's memory, not "
                         "the target's'. Two things this refuses to do: report an escape "
                         "rate of zero when no crashes were produced, which would let an "
                         "engine that refuses everything claim perfection; and count a "
                         "defect that never fired as a pass — sqlite3_open allocates a "
                         "handle even when it fails, so unchecked-handle never received the "
                         "NULL it depends on, and that is recorded as NO OBSERVATION. "
                         "Without -fork=1 -ignore_crashes=1 libFuzzer stops at the first "
                         "crash and the whole rate rested on n=4."),
        Deliverable("TF.ARTIFACT",
                    "provenance chain and the disclosure artifact", DONE,
                    modules=("hforge.findings.report", "hforge.findings.pipeline"),
                    cli=("triage",),
                    tests=("test_a_blocked_finding_is_not_reportable",
                           "test_the_artifact_carries_the_chain_a_maintainer_needs",
                           "test_the_pipeline_refuses_a_harness_owned_crash"),
                    note="verified end to end on a real heap overflow: harness-owned crash "
                         "refused, library-owned crash placed at rung 3 REPORTABLE with a "
                         "20-byte minimised input and its exclusions."),
    )),

    Phase("M", "the model gets hands on the engine, never on the arbiter", DONE, (
        Deliverable("M0.RING0",
                    "MCP server, ring 0: schema, gates, explain, platforms, validate", DONE,
                    modules=("hforge_mcp.server", "hforge_mcp.rings"),
                    tests=("test_initialize_and_call_round_trip",
                           "test_validate_returns_repairable_violations",
                           "test_only_permitted_rings_are_advertised"),
                    note="executes nothing. The repair loop lives here: every violation "
                         "carries `where` and `fix`, so a caller converges instead of "
                         "guessing. JSON-RPC over stdio with no third-party dependency."),
        Deliverable("M1.RING1",
                    "propose, targets, seed-mine, dict, audit, doctor — behind the "
                    "allow-list", DONE,
                    modules=("hforge_mcp.safety", "hforge_mcp.rings"),
                    tests=("test_ordinary_build_flags_are_allowed",
                           "test_flags_that_make_a_compiler_an_execution_primitive_are_refused",
                           "test_shell_metacharacters_are_refused",
                           "test_a_symlink_out_of_the_root_is_refused",
                           "test_ring_one_needs_a_declared_root"),
                    note="Ring 1 runs the C preprocessor, ldd and a compiler probe, so the "
                         "allow-list starts HERE, not at Ring 2. Case is load-bearing: an "
                         "earlier regex carried re.I and refused -O1 as though it were -o."),
        Deliverable("M2.BUDGET",
                    "measuring more candidates is affordable: cached mutants, wider --top",
                    DONE,
                    modules=("hforge.gates.dynamic_gates",),
                    tests=("test_d2_blocks_a_harness_that_cannot_find_a_planted_bug",),
                    note="CORRECTED: 'affordable' was overstated. Mutant GENERATION is "
                         "cached and a mutant build now recompiles only the changed "
                         "translation unit — a large win on a 33-file target like libmagic "
                         "and NOTHING on sqlite, whose single 243k-line amalgamation has no "
                         "other files to reuse. D2 is affordable on multi-file targets and a "
                         "deliberate expense on a large amalgamation. --top 12 -> 32."),
        Deliverable("M3.RING2",
                    "build and campaign, off by default, opt-in, and CONTAINED", DONE,
                    modules=("hforge_mcp.rings", "hforge_mcp.sandbox"),
                    tests=("test_ring_two_is_off_by_default",
                           "test_a_tool_call_cannot_raise_its_own_ring",
                           "test_ring_two_fails_closed_without_isolation",
                           "test_the_sandbox_states_what_it_guarantees",
                           "test_sandbox_run_refuses_when_unavailable"),
                    note="an allow-list narrows what a compiler accepts; it does not contain "
                         "what the compiled program does. Verified in the container: uid "
                         "1000, DNS unreachable, target read-only. FAILS CLOSED — refused "
                         "rather than silently run on the host."),
        Deliverable("M6.LOGS",
                    "three log channels, because stdout is the protocol", DONE,
                    modules=("hforge_mcp.server",),
                    tests=("test_stdout_carries_protocol_and_nothing_else",
                           "test_a_refusal_is_logged_as_a_warning",
                           "test_the_jsonl_log_survives_without_a_clean_exit",
                           "test_quiet_suppresses_stderr_but_not_the_file"),
                    note="the server had NO logging at all. stderr for a human and for an "
                         "MCP client, an appended JSONL file that survives a kill (unlike "
                         "--session-out, which only writes at exit), and MCP "
                         "notifications/message so a model sees its own refusals. A refusal "
                         "logs at warning: a boundary that stops something and says nothing "
                         "has no evidence it ever worked."),
        Deliverable("M5.LOOP",
                    "the repair loop, driven end to end through the server", DONE,
                    modules=("hforge_mcp.loop",),
                    tests=("test_the_repair_loop_converges_on_the_fix_strings_alone",
                           "test_the_loop_says_when_it_cannot_repair_rather_than_looping",
                           "test_the_loop_is_bounded"),
                    note="converges on the broken demo plan in 2 rounds using ONLY the `fix` "
                         "text the gates return. The deterministic repairer is the control, "
                         "not a stand-in: if it cannot converge, no model will do better on "
                         "the same output and the gate messages are what to fix."),
        Deliverable("M4.PRODUCER",
                    "a model proposes IR, behind a boundary that holds whoever proposes",
                    DONE,
                    modules=("hforge.producers.model",),
                    tests=("test_a_raw_block_from_a_model_is_refused",
                           "test_a_self_supplied_score_is_stripped_not_honoured",
                           "test_provenance_is_stamped_so_a_certificate_can_say_who_proposed_it",
                           "test_the_proposer_does_not_choose_what_gets_compiled",
                           "test_inline_c_in_an_op_is_refused",
                           "test_the_ranking_cannot_see_the_producer"),
                    note="deliberately calls no API: the boundary must hold whoever the "
                         "proposer is, and one tangled up with a vendor client is one that "
                         "gets bypassed the day the vendor changes."),
    )),

    Phase("L", "language coverage beyond C", PARTIAL, (
        Deliverable("L.CXX_PARSE",
                    "C++ headers: namespaces, classes, methods, overloads", DONE,
                    modules=("hforge.producers.cxx_header",),
                    tests=("test_namespaces_qualify_the_symbol",
                           "test_overloads_are_separated_by_arity",
                           "test_private_members_are_not_api",
                           "test_constructors_and_destructors_are_identified",
                           "test_a_template_is_skipped_with_a_reason",
                           "test_struct_is_public_by_default",
                           "test_byte_carrying_types_are_recognised"),
                    note="most of the target surface is C++ — poppler, ICU, protobuf, most "
                         "media and font libraries — so C-only capped the addressable field "
                         "at roughly half. Templates, exceptions across the boundary, "
                         "multiple inheritance and operator overloads are REPORTED as "
                         "skipped, not guessed at."),
        Deliverable("L.CXX_EMIT",
                    "C++ backend: objects, new/delete, std::string and vector inputs", DONE,
                    modules=("hforge.emit.cxx_libfuzzer",),
                    tests=("test_the_entry_point_is_extern_c",
                           "test_fuzzer_bytes_become_a_cxx_type",
                           "test_a_heap_object_is_new_and_the_method_is_called_through_it",
                           "test_the_c_backend_refuses_a_cxx_plan_and_vice_versa",
                           "test_an_unmappable_parameter_type_is_refused_not_guessed",
                           "test_the_replay_driver_uses_an_exactly_sized_buffer",
                           "test_the_build_command_is_cxx17"),
                    note="the IR needed NO change: a resource with a lifetime describes a "
                         "C++ object as well as a C handle. VERIFIED end to end — generated "
                         "harness compiled, fuzzed, and found a planted heap overflow in a "
                         "namespaced class, with S1 correctly warning about the missing "
                         "delete. `extern \"C\"` is required or libFuzzer never finds the "
                         "entry point: it compiles and silently does nothing."),
        Deliverable("L.CXX_PRODUCE",
                    "propose C++ plans automatically, as header_graph does for C", PLANNED,
                    note="the parser and the emitter exist; plan SYNTHESIS for C++ (which "
                         "constructor, which overload, object lifetime) is not written. The "
                         "verified run used a hand-authored plan."),
        Deliverable("L.ROUTER",
                    "emit dispatches on target.language; no caller names a backend", DONE,
                    modules=("hforge.emit",),
                    tests=("test_a_language_with_no_backend_is_refused_not_emitted_as_c",
                           "test_the_router_accepts_the_spellings_producers_actually_write"),
                    note="`Target.language` existed since Phase 1 and exactly ONE module read "
                         "it — cxx_libfuzzer, which read it in order to refuse. Nothing "
                         "dispatched: cli.py imported `emit` from c_libfuzzer by name, so a "
                         "second backend was reachable only from a test that imported it "
                         "directly. A language field nothing routes on is documentation. "
                         "plancheck C12 holds the rest of the codebase to the router."),
        Deliverable("L.JAVA_CLASSIFY",
                    "is an escaped exception a defect or the library's documented contract",
                    DONE,
                    modules=("hforge.java.exceptions",),
                    tests=("test_a_jvm_check_in_library_frames_is_a_defect",
                           "test_a_librarys_own_exception_type_is_recognised",
                           "test_a_declared_exception_is_the_contract_not_a_finding",
                           "test_an_exception_from_harness_frames_is_ours",
                           "test_the_last_caused_by_is_what_is_judged",
                           "test_resource_exhaustion_needs_a_ratio_not_a_threshold",
                           "test_no_ratio_stays_unmeasured_rather_than_becoming_a_claim"),
                    note="Java's S2 — the gate that pays for the module — and the reason the "
                         "build order puts it before the emitter. NumberFormatException from "
                         "a parser handed garbage IS the parser working; without this every "
                         "gate downstream judges noise. DEMONSTRATED LIVE: Jazzer, "
                         "unmodified, stopped on the FIRST input and reported the library's "
                         "own documented rejection as a crash. Java's bounds check is the "
                         "always-on memory-safety oracle, so an AIOOBE in library frames is "
                         "the moral equivalent of a sanitizer report. Two silent defects "
                         "found by running it: the trace parser required class names to end "
                         "in Exception/Error, so a library's OWN type (Parser$BadRecord) "
                         "matched nothing — the most common case, the one CONTRACT exists "
                         "for; and exhaustion is judged on a RATIO, never a threshold, "
                         "because 40 bytes consuming 2GB is a DoS and 2MB doing so is "
                         "arithmetic."),
        Deliverable("L.JAVA_PRODUCE",
                    "Java plans from bytecode: javap -> IR", DONE,
                    modules=("hforge.producers.java_api",), cli=("propose", "batch"),
                    tests=("test_javap_gives_the_throws_clause_a_c_header_cannot",
                           "test_autocloseable_is_a_declared_lifetime_not_an_inferred_one",
                           "test_the_declared_contract_travels_on_the_plan"),
                    note="bytecode is a far better source than headers: no preprocessor, no "
                         "macros, no BSD-style definitions, none of the four rewrites C "
                         "header parsing cost. It also gives two things a header cannot — the "
                         "THROWS CLAUSE (the library stating which exceptions are its "
                         "contract, which the classifier needs) and AutoCloseable, a "
                         "machine-readable lifetime where in C we infer a destructor from a "
                         "name and got sqlite3_finalize wrong for weeks. Contract gained "
                         "`declared_exceptions`, additive with a default."),
        Deliverable("L.JAVA_EMIT",
                    "Jazzer backend: FuzzedDataProvider harness + standalone replay driver",
                    DONE,
                    modules=("hforge.emit.java_jazzer",),
                    tests=("test_the_harness_catches_exactly_what_the_library_declares",
                           "test_a_supertype_is_never_caught_on_a_subclass_declaration",
                           "test_the_local_takes_the_declared_parameter_type_not_the_slice_kind",
                           "test_the_replay_driver_implements_every_method_the_emitter_can_generate",
                           "test_a_java_plan_may_not_carry_raw_blocks",
                           "test_a_c_shape_has_no_java_spelling_and_is_refused"),
                    note="we emit Jazzer harnesses for the same reason we emit libFuzzer ones "
                         "rather than building a fuzzer. FuzzedDataProvider IS the InputSlice "
                         "model, and `length_of` DISAPPEARS — the provider carries its own "
                         "length, so the entire (pointer,length) defect family that produced "
                         "sqlite3_prepare(db,sql,0,...) cannot be expressed. The harness "
                         "catches EXACTLY the exceptions the target declares and never a "
                         "supertype: that is the plan doing what `jazzer --autofuzz` cannot, "
                         "and it is measurable — unmodified, Jazzer halted on input #1 with "
                         "the library's own BadRecord; with the declared catch and "
                         "keep_going the same target ran 11.5M executions and reached the "
                         "planted defect. Two defects found by running it: the local's type "
                         "came from the SLICE KIND rather than the declared parameter, so a "
                         "boolean parameter got a byte; and the replay driver's provider "
                         "lacked consumeChar, so any char parameter produced a Replay.java "
                         "that did not compile and four gates read NOT_RUN 'the replay driver "
                         "was not built'."),
        Deliverable("L.JAVA_LADDER",
                    "a JVM ladder, because the C one is unreachable here", DONE,
                    modules=("hforge.java.ladder",),
                    tests=("test_the_contract_cannot_climb_the_ladder",
                           "test_a_defect_needs_an_independent_execution_mode_for_rung_three",
                           "test_a_sanitizer_report_reaches_rung_five_without_a_layout_argument",
                           "test_the_c_ladder_would_make_every_java_finding_unreportable",
                           "test_the_ladder_is_selected_by_language_not_overloaded"),
                    note="C rung 3 is 'a memory-safety violation' witnessed by a second "
                         "SANITIZER. There is no ASan for the JVM, so on the C ladder every "
                         "Java finding caps at rung 2, `reportable` is never true, and the "
                         "engine is inert while every gate reads green — the sqlite-chain "
                         "failure one layer up. Rung 3 here is 'a defect rather than the "
                         "documented contract'. Rung 3's independence has a real JVM answer: "
                         "-Xint versus the JIT, the same question decide_differential asks of "
                         "two Android instrumentation modes. Rung 5 INVERTS: a Jazzer "
                         "sanitizer is direct evidence a trust boundary was crossed and needs "
                         "no heap-layout argument, so it is easier to reach and stronger than "
                         "its C counterpart."),
        Deliverable("L.JAVA_GATES",
                    "the dynamic gates asked of the JVM, and the ones that do not apply",
                    DONE,
                    modules=("hforge.java.gates", "hforge.java.toolchain",
                             "hforge.java.sinks"),
                    gates=("D1", "D2", "D3", "D4", "D6", "D8", "D9"),
                    tests=("test_a_jvm_fault_is_read_from_output_never_from_the_exit_code",
                           "test_no_marker_at_all_is_a_broken_run_not_a_clean_one",
                           "test_a_fault_only_under_the_jit_is_refused_as_a_library_defect",
                           "test_the_highest_value_jvm_sink_would_score_zero_under_the_c_table",
                           "test_a_disarmed_sink_is_not_reported",
                           "test_the_emitted_replay_driver_compiles_and_finds_the_planted_defect",
                           "test_minimisation_shrinks_and_keeps_the_same_fault",
                           "test_a_reduction_that_changes_the_exception_is_not_a_reduction",
                           "test_d1_reads_the_constant_pool_for_the_target_call"),
                    note="VERIFIED end to end on a live Jazzer campaign: 20 edges, 11.5M "
                         "executions, 4 crashes — 2 classified CONTRACT and stopped at rung "
                         "1, 2 reaching rung 3 with independence from the -Xint differential. "
                         "D2 kills 3 of 4 planted defects. The load-bearing platform fact: a "
                         "JVM process dying of an uncaught exception exits 1, and so does a "
                         "missing file, a bad classpath and a JVM that would not start. "
                         "classify_exit would report `ok` for EVERY Java crash, so the driver "
                         "prints a marker and the fault is read from output — the Windows "
                         "NTSTATUS bug in a different runtime. D5 and D7 are NOT_RUN with "
                         "reasons rather than omitted: a certificate showing five passes and "
                         "no mention of D5 reads stronger than one saying D5 has no JVM "
                         "meaning. Three more defects found by running it: minimise replayed "
                         "INSIDE the `with` block on an unflushed temp file, so it always "
                         "reported 'did not shrink' (fixed: 204B -> 12B, the true minimum); "
                         "D9 BLOCKED a plan because one crash was a contract exception, "
                         "confusing 'this crash is not a finding' with 'this harness is "
                         "defective'; and Jazzer's ASM refuses class files newer than it "
                         "knows while reporting \"'Harness' not found on classpath\", which "
                         "sends you to debug a classpath that is correct."),
        Deliverable("L.OTHER", "JavaScript, Rust", PLANNED,
                    note="the IR is language-neutral and the router now exists, so each is a "
                         "producer plus an emitter. Java showed what else a language can "
                         "need: its own ladder, its own sink table, and its own answer to "
                         "'what is a fault'."),
    )),

    Phase("P4", "lift-and-grade third-party harnesses", PARTIAL, (
        Deliverable("P4.LIFT_C", "C harness -> IR", DONE,
                    modules=("hforge.lift.c_harness",),
                    tests=("test_lifts_a_harness_into_ops_and_resources",
                           "test_detects_use_after_destroy_in_someone_elses_harness",
                           "test_scalar_status_is_not_a_resource",
                           "test_out_parameter_creates_its_resource",
                           "test_a_prototype_is_not_a_harness",
                           "test_input_survives_a_memcpy"),
                    note="every test here pins a FALSE POSITIVE the lifter produced against "
                         "sqlite's real harnesses. The first four audits were noise and each "
                         "would have been a wasted report to a maintainer."),
        Deliverable("P4.CFLOW",
                    "control-flow aware lifting: conditions run, branches may not", DONE,
                    modules=("hforge.lift.cflow", "hforge.lift.c_harness"),
                    tests=("test_call_in_a_condition_is_seen_and_runs_unconditionally",
                           "test_a_branching_harness_can_now_be_graded_confidently",
                           "test_a_conditional_free_is_hedged_not_asserted",
                           "test_a_withheld_claim_is_withheld_whole"),
                    note="`if (sqlite3_open(path,&db)) return 0;` puts the call in the "
                         "CONDITION, which always runs. A statement regex anchored on ';' "
                         "never saw it, so db looked uncreated and every later use was "
                         "reported as use-before-create. That single miss caused most of "
                         "the false positives against sqlite's real harnesses."),
        Deliverable("P4.FIDELITY",
                    "refuse to report a finding the lift cannot support", DONE,
                    modules=("hforge.lift.c_harness", "hforge.cli"), cli=("audit",),
                    tests=("test_a_straight_line_harness_is_high_fidelity",
                           "test_low_attribution_still_disqualifies_a_lift"),
                    note="branches are modelled now, so they no longer disqualify a lift. "
                         "What does is unattributable VALUES: if most arguments are opaque, "
                         "the call graph reported is not the one that runs."),
        Deliverable("P4.AUDIT",
                    "audit public harnesses at scale and report violations", PARTIAL,
                    note="sqlite + file audited: 0 confident defects, 1 low-fidelity lift, "
                         "26 files correctly identified as not harnesses. Six separate "
                         "false-positive classes were found and fixed getting to that zero. "
                         "Scale (OSS-Fuzz corpus) and header-backed contract gates remain."),
    )),

    Phase("P5", "Windows and closed binary", PLANNED, (
        Deliverable("P5.TINYINST", "TinyInst coverage backend", PLANNED),
        Deliverable("P5.PE", "PE posture table and SEH-aware crash parsing", PLANNED),
    )),

    Phase("P6", "GUI track", PLANNED, (
        Deliverable("P6.TERM", "coverage-guided termination", PLANNED),
        Deliverable("P6.DROP", "file-drop driver", PLANNED),
        Deliverable("P6.DIALOG", "dialog automation: UIAutomation / AX API / AT-SPI", PLANNED),
    )),

    Phase("P7", "mobile: Android and iOS", PARTIAL, (
        Deliverable("P7.ANDROID", "NDK toolchain matrix, HWASan, tombstone oracle", PARTIAL,
                    note="VERIFIED on a live arm64-v8a API-35 emulator: cross-build, "
                         "device-aware detector selection, push-run and the instrumentation "
                         "differential all pass end to end. Still unverified: HWASan itself "
                         "(needs a _hwasan system image) and tombstone retrieval (needs a "
                         "rooted device; the unrooted path correctly reports that it cannot "
                         "read one). Binder/AIDL surface not started."),
        Deliverable("P7.IOS_SIM", "simulator-first discovery", PLANNED),
        Deliverable("P7.IOS_DEV", "device-side reachability oracle, .ips parser", PLANNED),
    )),

    Phase("P8", "snapshot and scale", PLANNED, (
        Deliverable("P8.SNAPSHOT", "target-embedded snapshotting on Windows", PLANNED),
        Deliverable("P8.LIBAFL", "LibAFL as the execution substrate", PLANNED),
    )),

    Phase("P9", "exotic targets", PLANNED, (
        Deliverable("P9.EMU", "QEMU-user and Unicorn for cross-architecture", PLANNED),
        Deliverable("P9.KERNEL", "kernel interfaces", PLANNED),
    )),
)


# Invariants the whole engine must hold, checked by plancheck rather than remembered.
DOCTRINE = (
    ("NOT_RUN_EXISTS",
     "a gate that could not run must report NOT_RUN with a reason, never PASS",
     "an absent check must never read as a satisfied one"),
    ("NO_BARE_BOOL",
     "no gate returns a bare boolean; every verdict carries its evidence",
     "a certificate a reader cannot check is not a certificate"),
    ("UNREACHABLE_ALWAYS",
     "every certificate states what the harness cannot find",
     "without it, 'we found nothing' and 'we could not have found anything' look alike"),
    ("MODEL_NEVER_CERTIFIES",
     "no producer may set a gate verdict; gates rank and confidence decides nothing",
     "the proposer may not be the prover"),
    ("RATE_NOT_BOOLEAN",
     "reproduction is reported as a rate, never as a yes/no",
     "a genuine bug measured 187/200; a one-shot replay lies 7% of the time"),
)


def phase(pid: str) -> Phase:
    for p in PHASES:
        if p.id == pid:
            return p
    raise KeyError(pid)


def all_deliverables() -> list:
    return [d for p in PHASES for d in p.deliverables]


def declared_gates() -> set:
    return {g for d in all_deliverables() for g in d.gates}


def summary() -> str:
    lines = []
    for p in PHASES:
        done = sum(1 for d in p.deliverables if d.status == DONE)
        lines.append(f"{p.id:<4} {p.status:<8} {done}/{len(p.deliverables):<3} {p.name}")
    return "\n".join(lines)
