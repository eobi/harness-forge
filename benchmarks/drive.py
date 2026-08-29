"""One benchmark case: propose -> pick the plan for the gold target -> build -> fuzz -> cover."""
import glob, json, os, pathlib, shutil, subprocess, sys
sys.path.insert(0, "/hf")
from hforge.producers import header_graph as hg
from hforge.emit import emit
from hforge.emit.c_libfuzzer import EmitError
from hforge.gates.static_gates import run_static_gates
from hforge.gates.result import BLOCK
from hforge.ir import Knobs, Target
from hforge.toolchain import check_emitted_c

CASES = {
 "libyaml/libyaml_loader_fuzzer": dict(
    hdr="/b/inc/yaml.h", inc=["/b/inc","/b/libyaml/include","/b/libyaml/src"],
    src=sorted(glob.glob("/b/libyaml/src/*.c")), fn="yaml_parser_load",
    cflags=['-DYAML_VERSION_STRING="0.2.5"','-DYAML_VERSION_MAJOR=0','-DYAML_VERSION_MINOR=2','-DYAML_VERSION_PATCH=5'],
    seeds=["/b/libyaml/tests","/b/libyaml/regression-inputs"],
    cover=["/b/libyaml/src/api.c","/b/libyaml/src/loader.c","/b/libyaml/src/parser.c","/b/libyaml/src/reader.c","/b/libyaml/src/scanner.c"]),
 "libyaml/libyaml_scanner_fuzzer": dict(
    hdr="/b/inc/yaml.h", inc=["/b/inc","/b/libyaml/include","/b/libyaml/src"],
    src=sorted(glob.glob("/b/libyaml/src/*.c")), fn="yaml_parser_scan",
    cflags=['-DYAML_VERSION_STRING="0.2.5"','-DYAML_VERSION_MAJOR=0','-DYAML_VERSION_MINOR=2','-DYAML_VERSION_PATCH=5'],
    # SCANNER SIDE ONLY. parser.c and loader.c are the layers ABOVE yaml_parser_scan
    # (scan -> parse -> load), 1,128 of 3,658 lines that no scanner harness can reach. A
    # whole-file denominator caps any scan harness at 69.2% and gold reports 70.6%, which
    # proves gold excludes them. Measured over the right set the scanner reads 70.47%,
    # not 48.74% — I hand-listed this wrong three times before checking.
    cover=["/b/libyaml/src/api.c","/b/libyaml/src/reader.c","/b/libyaml/src/scanner.c"]),
 "brotli/decode_fuzzer": dict(
    hdr="/b/brotli/c/include/brotli/decode.h", inc=["/b/brotli/c/include"],
    src=sorted(glob.glob("/b/brotli/c/common/*.c"))+sorted(glob.glob("/b/brotli/c/dec/*.c")),
    fn="BrotliDecoderDecompressStream", cflags=[],
    seeds=["/b/brotli/tests/testdata"],
    cover=sorted(glob.glob("/b/brotli/c/dec/*.c"))),
 "zopfli/zopfli_deflate_fuzzer": dict(
    hdr="/b/zopfli/src/zopfli/deflate.h",
    also=["/b/zopfli/src/zopfli/zopfli.h"], inc=["/b/zopfli/src/zopfli"],
    # zopfli_bin.c carries the CLI's own main(), which collides with libFuzzer's.
    src=[f for f in sorted(glob.glob("/b/zopfli/src/zopfli/*.c")) if "_bin" not in f],
    fn="ZopfliDeflate", cflags=[],
    cover=[f for f in sorted(glob.glob("/b/zopfli/src/zopfli/*.c")) if "_bin" not in f]),
 "zlib/zlib_uncompress2_fuzzer": dict(
    hdr="/b/zlib/zlib.h", inc=["/b/zlib"], src=sorted(glob.glob("/b/zlib/*.c")),
    fn="uncompress2", cflags=["-DHAVE_UNISTD_H"],
    cover=["/b/zlib/inflate.c","/b/zlib/inftrees.c","/b/zlib/inffast.c","/b/zlib/uncompr.c","/b/zlib/adler32.c","/b/zlib/crc32.c","/b/zlib/zutil.c"]),
 "yajl-ruby/json_fuzzer": dict(
    hdr="/b/yajl/inc/yajl/yajl_parse.h", inc=["/b/yajl/inc","/b/yajl/src","/b/yajl/src/api"],
    src=sorted(glob.glob("/b/yajl/src/*.c")), fn="yajl_parse", cflags=[],
    seeds=["/b/yajl/test/parsing/cases"],
    # PARSE SIDE ONLY. yajl_gen.c writes JSON, yajl_tree.c is a separate entry point, and
    # yajl_encode.c serves the writer — 647 of 1,636 lines that `yajl_parse` cannot reach.
    # A whole-library denominator caps ANY parse harness at 60.5%, and gold reports 69.1%,
    # which is only possible if gold excludes them too. Same argument as libyaml's emitter.
    cover=["/b/yajl/src/yajl.c","/b/yajl/src/yajl_alloc.c","/b/yajl/src/yajl_buf.c",
           "/b/yajl/src/yajl_lex.c","/b/yajl/src/yajl_parser.c"]),
 # ── Tier B from the native attack-surface map ─────────────────────────────
 # Real blast radius, a fraction of the scrutiny, and NO public OSS-Fuzz harness — which
 # is the case an LLM cannot have memorised. There is no gold or QuartetFuzz figure to
 # compare against here, and that is the point: this is where a harness generator has to
 # actually reason rather than recall.
 "lcms2/cmsOpenProfileFromMem": dict(
    hdr="/b/lcms2/include/lcms2.h", inc=["/b/lcms2/include","/b/lcms2/src"],
    src=sorted(glob.glob("/b/lcms2/src/*.c")), fn="cmsOpenProfileFromMem", cflags=[],
    seeds=["/b/lcms2/testbed"], max_len=65536,
    # PROFILE I/O ONLY. cmsOpenProfileFromMem reads an ICC profile; colour transforms,
    # gamma, CGATS and the PostScript writer are separate entry points it cannot reach.
    cover=["/b/lcms2/src/cmsio0.c","/b/lcms2/src/cmsio1.c","/b/lcms2/src/cmstypes.c",
           "/b/lcms2/src/cmsplugin.c","/b/lcms2/src/cmserr.c","/b/lcms2/src/cmsmd5.c",
           "/b/lcms2/src/cmsnamed.c","/b/lcms2/src/cmslut.c"]),
 "iperf/cjson_fuzzer": dict(
    hdr="/b/cjson/cJSON.h", inc=["/b/cjson"], src=["/b/cjson/cJSON.c"],
    fn="cJSON_Parse", cflags=[], cover=["/b/cjson/cJSON.c"]),
 # ── C++ targets ───────────────────────────────────────────────────────────
 # First C++ case in the suite. libde265 is C++ behind an `extern "C"` API, which is the
 # common shape for codecs and the one that matters most: the header producer can read the
 # C declarations, and only the build has to change to clang++.
 #
 # It is here for a second reason. libde265 ships its OWN hand-written fuzz harness at
 # fuzzing/stream_fuzzer.cc, so the gold column for this case is MEASURED on this machine
 # at this budget rather than cited from somebody's paper. Same compiler, same corpus
 # policy, same 600 seconds, same denominator. Run `benchmarks/targets/libde265.sh` first;
 # the build needs two headers cmake would otherwise generate.
 "libde265/stream_decode": dict(
    cxx=True, std="c++11",
    hdr="/b/libde265/libde265/de265.h",
    inc=["/b/libde265", "/b/libde265/libde265"],
    # en265.cc is the ENCODER's public API and it sits in the same directory as the
    # decoder. It pulls encoder_context and config_parameters out of encoder/, which is a
    # separate library this case does not build, so linking it fails on a dozen undefined
    # references that have nothing to do with decoding. Excluding it is the same argument
    # as the coverage denominator below, applied to the link line.
    src=[f for f in sorted(glob.glob("/b/libde265/libde265/*.cc"))
         if not f.endswith("/en265.cc")],
    fn="de265_push_data", cflags=["-DHAVE_CONFIG_H"], max_len=65536,
    # The library's own harness, built and measured exactly as ours is. This is a gold
    # figure this repository PRODUCES, not one it quotes.
    gold_harness="/b/libde265/fuzzing/stream_fuzzer.cc",
    # DECODE PATH ONLY. encoder/ is a separate library, the x86 and arm32 SIMD directories
    # are not compiled on aarch64, and sherlock265/dec265 are applications.
    cover=[f for f in sorted(glob.glob("/b/libde265/libde265/*.cc"))
           if not f.endswith("/en265.cc")]),
}

def main():
    case = sys.argv[1]; seconds = int(sys.argv[2]) if len(sys.argv) > 2 else 600
    c = CASES[case]
    # Some libraries declare the entry point in one header and its configuration helper in
    # another: ZopfliDeflate is in deflate.h, ZopfliInitOptions in zopfli.h. Give the
    # producer both, exactly as an operator would with --also-header.
    t = Target(name=case.split("/")[0],
               public_headers=[c["hdr"]] + list(c.get("also", [])),
               include_dirs=c["inc"],
               sources=c["src"], cflags=c["cflags"])
    # max_len is PER CASE. An ICC profile runs to 654 KB and a 4096-byte harness discards
    # every one of them at the door — `if (hf_size > 4096u) return 0;` — so the seeds are
    # mined, handed to libFuzzer, and thrown away by the harness itself.
    mlen = c.get("max_len", 4096)
    plans = hg.propose(t.public_headers, t, platforms=["linux-aarch64-glibc"],
                       knobs=Knobs(max_len=mlen))
    # Any plan that CALLS the gold target function, in whatever role. `cJSON_Parse(const
    # char *)` returns a handle, so our producer uses it as the CONSTRUCTOR — which is
    # exactly what the gold harness does (parse then delete). Insisting the target be the
    # `o_consume` op would score that a miss when the harness is right.
    cands = [p for p in plans if any(o.api == c["fn"] for o in p.sequence)]
    # Prefer plans where the fuzzer's bytes actually reach that call.
    def _driven(pl):
        op = next((o for o in pl.sequence if o.api == c["fn"]), None)
        return 1 if op and any(a.source == "input" for a in op.args) else 0

    def _is_entry(pl):
        """The gold target must be the ENTRY POINT, not an incidental setup call.

        Relaxing this to "any plan that calls the function" picked, for libyaml's scanner
        case, a plan whose consumer was `yaml_parser_set_input` — which takes a read-handler
        CALLBACK, bound to NULL — with `yaml_parser_scan` demoted to a setup op. The harness
        aborted after 2 executions and scored 0.00%.
        """
        return 1 if any(o.id.startswith("o_consume") and o.api == c["fn"]
                        for o in pl.sequence) else 0

    def _plain(pl):
        """Prefer the plan WITHOUT extra setup calls.

        A `_setup` variant inserts other library calls around the target, and for libyaml
        that meant `yaml_parser_load` beside `yaml_parser_scan` — which libyaml forbids on
        one parser and asserts on. Ranking by deepest sequence chose it every time.
        """
        return 0 if ("_setup" not in pl.name and "_with_" not in pl.name) else 1

    cands.sort(key=lambda x: (-_is_entry(x), -_driven(x), _plain(x),
                              -len(x.sequence), len(x.name)))
    out = {"case": case, "engine": os.environ.get("HF_ENGINE_SHA", "unknown"),
           "target": c["fn"], "proposed": len(plans),
           "plans_for_target": len(cands)}
    if not cands:
        out["result"] = "NO PLAN for the gold target"
        print(json.dumps(out)); return
    ok = []
    for p in cands:
        rs = run_static_gates(p)
        b = sorted({v.code for r in rs for v in r.violations if v.severity == BLOCK})
        if not b:
            ok.append(p)
    out["passed_static"] = len(ok)
    if not ok:
        out["result"] = "all plans for the gold target were refused by a static gate"
        print(json.dumps(out)); return
    # prefer the plan with the most ops (deepest lifecycle), then the shortest name
    p = sorted(ok, key=lambda x: (-_is_entry(x), -_driven(x), _plain(x),
                                  -len(x.sequence), len(x.name)))[0]
    out["target_is_input_driven"] = bool(_driven(p))
    out["target_is_entry_point"] = bool(_is_entry(p))
    out["plan"] = p.name
    out["sequence"] = [o.api for o in p.sequence]
    try:
        e = emit(p)
    except EmitError as ex:
        out["result"] = f"emit refused: {ex}"; print(json.dumps(out)); return
    wd = pathlib.Path(f"/b/runs/{case.replace('/','__')}"); wd.mkdir(parents=True, exist_ok=True)
    (wd/"harness.c").write_text(e.source)

    # KEEP EVERY RUN'S EVIDENCE ON DISK.
    #
    # A benchmark row is a summary, and a summary cannot be audited. Three of this
    # project's four wrong diagnoses were caught by re-reading a raw libFuzzer log
    # after the number had already been written down: `corp: 1/1b` with coverage
    # frozen at 42 is what exposed the scratch-initialisation bug, and no JSON
    # field would have shown it. So the log outlives the run.
    logs = pathlib.Path(os.environ.get("HF_LOGDIR", "/b/logs")) / case.replace("/", "__")
    logs.mkdir(parents=True, exist_ok=True)
    (logs/"harness.c").write_text(e.source)
    (logs/"plan.hir.json").write_text(json.dumps(p.to_json() if hasattr(p, "to_json")
                                                 else {"name": p.name,
                                                       "sequence": [o.api for o in p.sequence]},
                                                 indent=2, default=str))
    out["logs"] = str(logs)
    # C++ targets build with clang++ and an explicit standard. Everything else about the
    # build is identical, on purpose: a gold harness and ours must differ in the harness
    # and in nothing else, or the comparison measures the build.
    cc = ["clang++", f"-std={c.get('std','c++11')}"] if c.get("cxx") else ["clang"]

    # ── the emitted C is ours; a warning about it is evidence about the producer ──
    #
    # This case cost two 600-second campaigns and three wrong diagnoses. The emitter
    # declared `unsigned char hf_r_err` for a function returning `unsigned char *`, clang
    # warned, the build succeeded, and the harness segfaulted on its third execution for a
    # measured 0.00% where the case had been 65.12%. The compiler knew in milliseconds.
    diag = check_emitted_c(cc[0], wd/"harness.c", c["inc"], c["cflags"],
                           is_cxx=bool(c.get("cxx")))
    if diag:
        (logs/"emitter-defect.log").write_text("\n".join(diag) + "\n")
        out["result"] = "REFUSED: the emitted harness has an emitter defect"
        out["emitter_defect"] = diag[:3]
        print(json.dumps(out))
        return

    binp = wd/"fuzz"
    cmd = cc + ["-g","-O1","-fno-omit-frame-pointer",
           "-fprofile-instr-generate","-fcoverage-mapping"]
    cmd += [f"-I{i}" for i in c["inc"]] + c["cflags"]
    cmd += ["-fsanitize=fuzzer,address", str(wd/"harness.c")] + c["src"] + ["-o", str(binp)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    (logs/"build.cmd").write_text(" ".join(cmd) + "\n")
    # A build.log left over from an EARLIER failed attempt sits next to a successful build
    # and reads as if this run failed. run-010's first attempt failed to link en265.cc; the
    # retry succeeded into the same directory and the stale log stayed. Evidence that
    # describes a different run is worse than no evidence.
    (logs/"build.log").unlink(missing_ok=True)
    if r.returncode != 0:
        # The truncated field in the JSON row is for reading; the file is for fixing.
        (logs/"build.log").write_text(r.stdout + r.stderr)
        out["result"] = "build failed"; out["error"] = r.stderr[-400:]
        print(json.dumps(out)); return
    corp = wd/"corpus"; corp.mkdir(exist_ok=True)

    # THE ENGINE ALREADY MINES BOTH OF THESE AND THE BENCHMARK WAS USING NEITHER.
    # Measured on sqlite, the dictionary alone took one harness from 867 to 5,441 edges
    # (6.3x) on the same budget. Running the benchmark with an empty corpus and no
    # dictionary measured the producer with two of the engine's own instruments switched
    # off — a fault in the benchmark, not in the engine.
    from hforge.analysis import dictionary, seeds as seedmod
    dict_args = []
    dpath = wd/"target.dict"
    if dictionary.write(c["src"], dpath):
        dict_args = [f"-dict={dpath}"]
    n_seeds = 0
    if c.get("seeds"):
        # Seeds are capped at the harness's own max_len, not an arbitrary 4096: lcms2's ICC
        # profiles run to 654 KB and every one was silently rejected, and 8 of brotli's 44
        # streams too.
        mined = seedmod.mine(c["seeds"], max_bytes=65536)
        n_seeds = seedmod.write(mined, corp)
    out["dictionary"] = bool(dict_args)
    out["seeds"] = n_seeds
    prof = wd/"run.profraw"
    env = dict(os.environ, LLVM_PROFILE_FILE=str(prof))
    fr = subprocess.run([str(binp), str(corp), *dict_args, f"-max_total_time={seconds}",
                         "-print_final_stats=1", f"-max_len={mlen}"],
                        capture_output=True, text=True, errors="replace",
                        env=env, timeout=seconds+300)
    log = fr.stdout + fr.stderr
    (logs/"fuzz.log").write_text(log)
    (logs/"fuzz.cmd").write_text(
        " ".join([str(binp), str(corp), *dict_args, f"-max_total_time={seconds}",
                  "-print_final_stats=1", f"-max_len={mlen}"]) + "\n")
    if dict_args and dpath.exists():
        (logs/"target.dict").write_text(dpath.read_text(errors="replace"))
    out["executions"] = int(next((x for x in __import__("re").findall(
        r"stat::number_of_executed_units:\s*(\d+)", log)), 0) or 0)
    subprocess.run(["llvm-profdata-14","merge","-sparse",str(prof),"-o",str(wd/"run.profdata")],
                   capture_output=True)
    # THE DENOMINATOR IS DERIVED, NOT HAND-LISTED.
    #
    # I hand-listed cover files three times and was wrong three times: libyaml's loader
    # included the emitter side, yajl included the generator and tree, and the scanner
    # included parser.c and loader.c — the layers ABOVE yaml_parser_scan. Each time the
    # engine looked far worse than it was; the scanner reads 48.74% over the wrong file set
    # and 70.47% over the right one, against a gold harness at 70.6%.
    #
    # So ask the engine. D4's call-graph walk already computes what an entry point reaches;
    # a file with no reachable function in it cannot be part of the denominator, and gold's
    # own numbers prove it excludes them too (they exceed the ceiling otherwise).
    # The automatic derivation is left OFF: `reachable_from` is a name-based closure that
    # over-approximates (its own docstring says so), and for libyaml it pulled parser.c and
    # loader.c back in because yaml_parser_scan appears in their call graphs as a callee.
    # Each cover list below carries the ceiling argument that justifies it.
    # The coverage denominator is HAND-LISTED per case, with the ceiling argument that
    # justifies it recorded beside each list. Automatic derivation was tried and removed:
    # `reachable_from` is a name-based closure that over-approximates — for libyaml it pulled
    # parser.c and loader.c back in because yaml_parser_scan appears in their call graphs as
    # a callee, which is exactly the file set that made the scanner read 48.74% instead of
    # 70.47%.
    cover = c["cover"]
    out["cover_files"] = [f.rsplit("/", 1)[-1] for f in cover]
    cr = subprocess.run(["llvm-cov-14","report",str(binp),
                         f"-instr-profile={wd}/run.profdata"] + cover,
                        capture_output=True, text=True)
    # The TOTAL row is the only thing the JSON carries, but the per-file breakdown is
    # what makes a denominator argument checkable by someone who does not trust ours.
    (logs/"coverage.txt").write_text(cr.stdout + cr.stderr)
    tot = [l for l in cr.stdout.splitlines() if l.startswith("TOTAL")]
    if tot:
        f = tot[0].split()
        out["regions_pct"] = f[3].rstrip('%'); out["functions_pct"] = f[6].rstrip('%')
        out["lines_pct"] = f[9].rstrip('%'); out["branches_pct"] = f[12].rstrip('%')
    out["result"] = "measured"

    # ── the gold harness, when the project ships one ──────────────────────────────
    #
    # Every other gold figure in this suite is CITED from somebody else's paper, which
    # means it was produced on another machine, with another compiler, at another budget,
    # over a denominator we cannot inspect. When a project ships its own hand-written fuzz
    # harness in tree, none of that is necessary: build it here, run it here, measure it
    # over the same file list, and the comparison differs in the harness and in nothing
    # else. That is a stronger claim than any citation, and it can go against us.
    if c.get("gold_harness"):
        g = measure_gold(c, wd, logs, corp, dict_args, seconds, mlen, cover)
        out["gold_measured_here"] = g

    print(json.dumps(out))


def measure_gold(c, wd, logs, corp, dict_args, seconds, mlen, cover):
    """Build and run the project's own harness under exactly our build and budget."""
    gsrc = c["gold_harness"]
    gwd = wd/"gold"; gwd.mkdir(exist_ok=True)
    glogs = logs/"gold"; glogs.mkdir(exist_ok=True)
    gbin = gwd/"fuzz"
    cc = ["clang++", f"-std={c.get('std','c++11')}"] if c.get("cxx") else ["clang"]
    cmd = cc + ["-g", "-O1", "-fno-omit-frame-pointer",
                "-fprofile-instr-generate", "-fcoverage-mapping"]
    cmd += [f"-I{i}" for i in c["inc"]] + c["cflags"]
    cmd += ["-fsanitize=fuzzer,address", gsrc] + c["src"] + ["-o", str(gbin)]
    (glogs/"build.cmd").write_text(" ".join(cmd) + "\n")
    (glogs/"build.log").unlink(missing_ok=True)
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        (glogs/"build.log").write_text(r.stdout + r.stderr)
        return {"result": "build failed", "error": r.stderr[-400:]}

    # A FRESH corpus. Handing the gold harness the corpus OUR run just grew would measure
    # our corpus, not their harness, and it would flatter us: those inputs were selected
    # by a fuzzer driving our entry point. Same seeds and same dictionary, same start.
    gcorp = gwd/"corpus"
    if gcorp.exists():
        shutil.rmtree(gcorp)
    gcorp.mkdir()
    if c.get("seeds"):
        from hforge.analysis import seeds as seedmod
        seedmod.write(seedmod.mine(c["seeds"], max_bytes=65536), gcorp)
    prof = gwd/"run.profraw"
    fr = subprocess.run([str(gbin), str(gcorp), *dict_args, f"-max_total_time={seconds}",
                         "-print_final_stats=1", f"-max_len={mlen}"],
                        capture_output=True, text=True, errors="replace",
                        env=dict(os.environ, LLVM_PROFILE_FILE=str(prof)),
                        timeout=seconds + 300)
    (glogs/"fuzz.log").write_text(fr.stdout + fr.stderr)
    subprocess.run(["llvm-profdata-14", "merge", "-sparse", str(prof),
                    "-o", str(gwd/"run.profdata")], capture_output=True)
    cr = subprocess.run(["llvm-cov-14", "report", str(gbin),
                         f"-instr-profile={gwd}/run.profdata"] + cover,
                        capture_output=True, text=True)
    (glogs/"coverage.txt").write_text(cr.stdout + cr.stderr)
    g = {"result": "measured", "source": gsrc}
    tot = [l for l in cr.stdout.splitlines() if l.startswith("TOTAL")]
    if tot:
        f = tot[0].split()
        g["regions_pct"], g["lines_pct"] = f[3].rstrip("%"), f[9].rstrip("%")
    g["executions"] = int(next((x for x in __import__("re").findall(
        r"stat::number_of_executed_units:\s*(\d+)", fr.stdout + fr.stderr)), 0) or 0)
    return g

main()
