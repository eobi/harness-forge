"""Does the WIDER candidate space contain a better harness?

`probe_select.py` asked whether the static tie-break costs coverage and answered no: 0.63
points on libyaml against a run-to-run variance of 3.55, and 0.00 on libpng. The gap against
OGHarn is not the ranking, it is the CANDIDATE SPACE -- the header graph proposes one plan
per consuming entry point and never calls a function belonging to a different entry point
against the same object.

`hforge/producers/mutate.py` generates those, and the reachable-surface measurement says it
widens jansson from 7 exported functions to 43. That is a CEILING. This asks the question
the ceiling cannot: does any of that extra reach turn into coverage?

    docker run --rm -v "$PWD:/hf:ro" -v /tmp/hf-bench:/b hforge-linuxbench \\
        python3 /hf/benchmarks/probe_synth.py jansson/json_loadb 120

WHY THE CASE MATTERS MORE THAN THE METHOD. woff2 was re-measured at n=5 on a quiet host and
returned an exact Mann-Whitney p of 1.0: it runs with no seed corpus, so each campaign is a
random walk and the spread is 24-31 points. A case like that cannot answer this question
however carefully it is asked. Use seeded, low-variance cases -- pugixml returned the same
figure five times with a spread of 0.00.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

sys.path.insert(0, "/hf")

from hforge.gates.static_gates import BLOCK, run_static_gates   # noqa: E402
from hforge.ir import Knobs, Target                             # noqa: E402
from hforge.producers import header_graph as hg                 # noqa: E402
from hforge.producers import mutate                             # noqa: E402

sys.path.insert(0, "/hf/benchmarks")
from drive import CASES                                         # noqa: E402
from hforge.emit import emit                                 # noqa: E402
from probe_select import probe, rank_key                        # noqa: E402


def _passes(p) -> bool:
    return not [v for r in run_static_gates(p)
                for v in r.violations if v.severity == BLOCK]


def main() -> int:
    case = sys.argv[1]
    seconds = int(sys.argv[2]) if len(sys.argv) > 2 else 120
    cap = int(sys.argv[3]) if len(sys.argv) > 3 else 12
    c = CASES[case]
    mlen = c.get("max_len", 4096)
    t = Target(name=case.split("/")[0],
               public_headers=[c["hdr"]] + list(c.get("also", [])),
               include_dirs=c["inc"], sources=c["src"], cflags=c["cflags"])

    plans = hg.propose(t.public_headers, t, platforms=["linux-aarch64-glibc"],
                       knobs=Knobs(max_len=mlen))
    named = [p for p in plans if any(o.api == c["fn"] for o in p.sequence)]
    base = [p for p in named if _passes(p)]

    # Synthesise from the SOUND bases only. Mutating an invalid plan cannot make it valid,
    # and measuring the result reports the base plan's quality rather than the mutation's.
    synth_all, stats = mutate.synthesize(base)
    synth = [s for s in synth_all if _passes(s)
             and any(o.api == c["fn"] for o in s.sequence)]

    print(f"{case}: {len(plans)} proposed, {len(named)} name the target, "
          f"{len(base)} pass the gates")
    print(f"  synthesised {len(synth_all)} candidates, {len(synth)} valid and on-target")
    if not base:
        print("  no sound base plan; nothing to widen")
        return 0

    # The base pool is ranked by the shipping rule; the synth pool is capped so one case
    # cannot run for a day. The cap is PRINTED, because a silent truncation reads as
    # "we tried everything" when it is not.
    base_ranked = sorted(base, key=lambda x: rank_key(x, c["fn"]))

    # A MUTANT IS ONLY AS GOOD AS WHAT IT GREW FROM, SO ORDER BY THE BASE.
    #
    # The first version of this ranked the synth pool by gate evidence alone and capped it
    # at ten. On libyaml that campaigned ten mutants of `yaml_parser_scan_setup` and
    # `yaml_parser_parse_setup` -- two base plans that themselves score 0.00% -- and never
    # reached a single mutant of `yaml_parser_load`, the base that works at 71.79%. The run
    # reported "synth best 0.00%, gain -71.79 points", which measured nothing except my own
    # ordering.
    #
    # Candidates are named `{base}__widen_x` / `{base}__repeat_x`, so each one is grouped
    # under its base and the groups are taken in the base's own rank order.
    _order = {pl.name: i for i, pl in enumerate(base_ranked)}

    def _from(pl):
        stem = pl.name.split("__widen_")[0].split("__repeat_")[0]
        return _order.get(stem, len(_order))

    synth_ranked = sorted(synth, key=lambda x: (_from(x), rank_key(x, c["fn"])))[:cap]
    if len(synth) > cap:
        print(f"  NOTE: {len(synth) - cap} synthesised candidate(s) NOT campaigned "
              f"(cap {cap}); the comparison is against the first {cap} by gate evidence")

    cc = ["clang++", f"-std={c.get('std','c++11')}"] if c.get("cxx") else ["clang"]

    # A SMOKE TEST BEFORE THE CAMPAIGN. Static gates cannot see an ordering constraint that
    # lives in an assert.
    #
    # `yaml_parser_set_encoding` asserts `!parser->encoding`, so calling it after the parser
    # has read input aborts. The synthesised candidate that does exactly that passes every
    # static gate, builds cleanly, and then dies on the FIRST input -- and its campaign
    # returned 0.00% while looking like a measurement. No header declares that constraint;
    # only running the thing finds it.
    #
    # This is the honest qualification of the bet this module rests on. Static rejection is
    # microseconds and worth having, but it does not replace execution: it reduces what has
    # to be executed. Two seconds per candidate here, against ninety for a campaign.
    def smoke(pl, work):
        try:
            e = emit(pl)
        except Exception:
            return False, "emit refused"
        work.mkdir(parents=True, exist_ok=True)
        src = work / "h.c"
        src.write_text(e.source if hasattr(e, "source") else e.code)
        binp = work / "smoke"
        cmd = cc + ["-g", "-fsanitize=fuzzer", str(src), *c["src"],
                    *[f"-I{i}" for i in c["inc"]], *c["cflags"], "-o", str(binp)]
        if subprocess.run(cmd, capture_output=True, text=True).returncode != 0:
            return False, "build failed"
        seed = work / "seed"
        seed.mkdir(exist_ok=True)
        (seed / "s").write_bytes(b"a: 1\n")
        r = subprocess.run([str(binp), str(seed), "-runs=64",
                            f"-max_len={mlen}"], capture_output=True, text=True, timeout=60)
        return r.returncode == 0, ("aborts on a valid input" if r.returncode else "ok")
    root = pathlib.Path("/b/synth") / case.replace("/", "__")
    out = {"case": case, "seconds": seconds, "base": [], "synth": [],
           "synth_generated": len(synth_all), "synth_valid": len(synth),
           "synth_campaigned": len(synth_ranked), "stats": stats}

    for i, pl in enumerate(base_ranked):
        cov, note = probe(pl, c, cc, root / f"b{i:02d}", seconds, mlen)
        out["base"].append({"plan": pl.name, "cov": cov, "note": note})
        print(f"  BASE  {pl.name[:44]:46} {(f'{cov:.2f}%' if cov is not None else note):>12}")
    survived, killed = [], []
    for i, pl in enumerate(synth_ranked):
        ok_, why = smoke(pl, root / f"k{i:02d}")
        (survived if ok_ else killed).append((pl, why))
    out["smoke_killed"] = [{"plan": pl.name, "why": w} for pl, w in killed]
    if killed:
        print(f"  SMOKE TEST killed {len(killed)} of {len(synth_ranked)} before campaigning:")
        for pl, w in killed[:6]:
            print(f"      {pl.name[:52]:54} {w}")
    for i, (pl, _w) in enumerate(survived):
        cov, note = probe(pl, c, cc, root / f"s{i:02d}", seconds, mlen)
        out["synth"].append({"plan": pl.name, "cov": cov, "note": note})
        print(f"  SYNTH {pl.name[:44]:46} {(f'{cov:.2f}%' if cov is not None else note):>12}")

    bv = [r["cov"] for r in out["base"] if r["cov"] is not None]
    sv = [r["cov"] for r in out["synth"] if r["cov"] is not None]
    if bv:
        out["base_best"] = max(bv)
    if sv:
        out["synth_best"] = max(sv)
    if bv and sv:
        out["gain_points"] = round(max(sv) - max(bv), 4)
        out["gain_pct"] = round(100 * (max(sv) - max(bv)) / max(bv), 2) if max(bv) else None
        print(f"\n  base best  {max(bv):.2f}%")
        print(f"  synth best {max(sv):.2f}%")
        print(f"  GAIN {out['gain_points']:+.2f} points"
              + (f"  ({out['gain_pct']:+.1f}%)" if out.get("gain_pct") is not None else ""))
        print("\n  ONE SAMPLE PER CANDIDATE. A gain here is a reason to run it n=5, not a"
              "\n  result: this repository has already retracted a 1.31x that came from one"
              "\n  run and became p = 1.0 at five.")
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
