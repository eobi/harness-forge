"""Static gates — run on the plan, before a compiler exists.

This is where Harness Forge goes past the published work. The Four Principles framework
probes a *compiled* harness with reach and run checks; but lifetime correctness, protocol
compliance and call ordering are properties of the plan, and checking a plan is strictly
stronger than checking one execution of a binary built from it.

Six gates, mapped to the published correctness principles:

  S1  lifetime          resources created once, destroyed once, never used after   P1
  S2  contract          NUL-termination, (ptr,len) pairs, ownership, non-null      P2
  S3  ordering          create before use before destroy                           P2
  S4  boundary          public headers only; no internal-symbol bypass             P3
  S5  input flow        every slice is consumed; the target actually sees input    P4
  S6  error handling    failure returns are checked before dependent use           P1

S2 is the one that pays for the whole module. Feeding an exact-size buffer to an API whose
contract requires NUL termination makes *every* input a crash, which is how a cJSON harness
in LAB-07 produced eight false findings against a library that was behaving correctly. That
defect is visible in the plan without building anything.

Pure functions of a HarnessIR. No I/O, no subprocess, no model.
"""
from __future__ import annotations

import re

from ..ir import (
    SOURCES, SRC_SCRATCH, SRC_SCRATCH_ADDR,
    HarnessIR, Op, ROLE_CREATE, ROLE_DESTROY, ROLE_CONSUME, ROLE_QUERY, ROLE_RESET,
    SRC_INPUT, SRC_RESOURCE, SRC_LENGTH_OF, SRC_LITERAL, SRC_OUT, ROLES, SLICE_KINDS,
)
from .result import BLOCK, WARN, INFO, GateResult, Violation, decide, passed

ALL_STATIC = ("S1", "S2", "S3", "S4", "S5", "S6")


# ── S1 — lifetime ─────────────────────────────────────────────────────────────

def s1_lifetime(ir: HarnessIR) -> GateResult:
    """Every resource is created exactly once, destroyed exactly once, and never touched
    after destruction. A stale handle in the plan is a use-after-free in the harness, and
    the crash it produces belongs to us, not to the target."""
    v: list[Violation] = []
    UNBORN, ALIVE, DEAD = 0, 1, 2
    # A CALLER-DECLARED OUT SLOT IS ALIVE FROM ITS DECLARATION.
    #
    # `json_error_t err; json_loadb(buf, n, 0, &err);` — the harness declares and zeroes it
    # and the LIBRARY fills it. No call creates it, so scoring it UNBORN reported
    # S1.USE_BEFORE_CREATE against a correct plan, and jansson's only entry point was
    # refused. There is also nothing to destroy: it is storage, not a lifetime the library
    # manages. The IR says which kind it is; the gate reads that rather than inferring it.
    # THIS TEST WAS WRITTEN AGAINST A STORAGE VALUE THAT DOES NOT EXIST. The IR spells the
    # kinds `handle | inline | out_param`; this read `== "out"`, which never matches, so the
    # jansson fix the comment above describes has never once fired. Every caller-declared
    # slot has been scored UNBORN since it was written, and that single mismatch produced
    # the USE_BEFORE_CREATE flags against yajl-ruby, bluez, lcms and tdengine in the
    # OSS-Fuzz fleet audit. `Resource.by_address` is the IR's own name for the property, so
    # the gate asks the IR instead of re-spelling it and getting it wrong again.
    state = {r.id: (ALIVE if r.by_address else UNBORN) for r in ir.resources}
    _by_addr = {r.id: r.by_address for r in ir.resources}
    born_arm: dict = {}

    def _arm_of(op) -> str:
        for x in op.guarded_by:
            if x.startswith("__branch:"):
                return x.split(":", 1)[1]
        return ""

    def _exits(op) -> bool:
        return any(x.startswith("__exits:") for x in op.guarded_by)

    def _unreachable_from(dead_in: str, dead_exits: bool, here: str) -> bool:
        """Did the destroy happen on a path that cannot reach HERE?

        Either the two arms are mutually exclusive, or the destroying arm left the
        function -- in which case only statements inside that same arm follow it.
        """
        if _exclusive(dead_in or "", here or ""):
            return True
        return bool(dead_exits and dead_in
                    and not (here or "").startswith(dead_in))

    def _exclusive(a, b) -> bool:
        from ..lift.cflow import mutually_exclusive
        return mutually_exclusive(a or "", b or "")
    born_at: dict[str, str] = {}
    # Ownership is needed at CREATE time, not only at the end: a slot refilled from an
    # arena is not a leak of the first value. Built up-front from the sequence.
    _owner_early: dict = {}
    for _op in ir.sequence:
        if not _op.binds:
            continue
        for _a in _op.args:
            if _a.source == SRC_RESOURCE and _a.ref != _op.binds:
                _owner_early[_op.binds] = _a.ref
                break
    _destroyed_anywhere = {o.targets for o in ir.sequence if o.targets}

    def _owned_by_a_released_arena(rid: str, seen=None) -> bool:
        seen = seen or set()
        own = _owner_early.get(rid)
        if not own or own in seen:
            return False
        seen.add(own)
        return own in _destroyed_anywhere or _owned_by_a_released_arena(own, seen)

    # AN ALLOCATION THAT MIGHT FAIL, USED AS IF IT CANNOT.
    #
    # `p = thing_new(); thing_use(p);` dereferences NULL on every out-of-memory input, and
    # under a fuzzer that is a crash attributed to the LIBRARY when it belongs to the
    # harness. This is the first check here that is about the harness's own logic rather
    # than about resource lifetime, and it is the class QuartetFuzz calls logic correctness.
    #
    # A pointer counts as checked if EITHER shape appears:
    #   `if (p) { use(p); }`        -- the use sits under a positive test
    #   `if (!p) return 0;`         -- an earlier arm tested it and LEFT
    # The second is why guard text and the exiting-arm marker both had to reach the gates.
    def _is_a_null_fallback(op) -> bool:
        """`x = parse(..); if (x == NULL) x = new_object();` is a FALLBACK, not a second
        create.

        The second assignment runs only when the first produced nothing, so there is no
        first value to leak. The mirror image of the rule that a destroy guarded by a
        POSITIVE null-test is unconditional cleanup -- json-c's pointer fuzzer uses this
        shape and read as a double create.
        """
        g = ""
        for x in op.guarded_by:
            if x.startswith("__guard:"):
                g = x.split(":", 1)[1]
        if not g or "||" in g or not op.binds:
            return False
        name = op.binds[2:] if op.binds.startswith("r_") else op.binds
        n = re.escape(name)
        return bool(re.search(r"!\s*" + n + r"\b", g)
                    or re.search(r"\b" + n + r"\s*==\s*(?:NULL|nullptr|0)\b", g)
                    or re.search(r"\b(?:NULL|nullptr|0)\s*==\s*" + n + r"\b", g))

    def _guard_of(op) -> str:
        for x in op.guarded_by:
            if x.startswith("__guard:"):
                return x.split(":", 1)[1]
        return ""

    def _tests(guard: str, names) -> bool:
        for n in names:
            if re.search(r"(?<![\w.>])" + re.escape(n) + r"\b", guard or ""):
                return True
        return False

    _names_of = {}
    for _r in ir.resources:
        _names_of[_r.id] = [_r.id[2:]] if _r.id.startswith("r_") else [_r.id]

    # Only a handle the harness CREATED can be NULL from a failed allocation. A slot the
    # caller declared has storage from its declaration, and an inline object cannot be NULL
    # at all.
    _storage_of = {r.id: (r.storage or "handle") for r in ir.resources}
    _created_by_call = {op.binds for op in ir.sequence if op.binds}

    # The lifter answers this from the control flow, because the commonest check --
    # `if (p == NULL) return 0;` -- has a body containing only a return and therefore
    # produces no op for a gate to read.
    _checked: set = {r.id for r in ir.resources if getattr(r, "null_checked", False)}
    for op in ir.sequence:
        _g = _guard_of(op)
        if _g and any(x.startswith("__exits:") for x in op.guarded_by):
            # An arm that tested something and left makes it safe below.
            for rid, names in _names_of.items():
                if _tests(_g, names):
                    _checked.add(rid)

    cleared: set = set()            # slots an explicit `x = NULL` emptied
    dead_by: dict[str, str] = {}    # ...and WHICH call did it, for two-phase teardown
    dead_exits: dict[str, bool] = {}  # ...and whether that path left the function
    dead_arm: dict[str, str] = {}   # WHERE a resource died, for the same reason born_arm exists

    for op in ir.sequence:
        api = ir.api_of(op)
        if api is None:
            continue

        # uses first: an argument referencing a resource requires it to be alive.
        #
        # Except for the op that CREATES a caller-allocated resource, which necessarily
        # references it — `yaml_parser_initialize(&parser)` receives the very object it is
        # about to initialise. That is the creation, not a use before it. The storage
        # already exists in both cases; what the initialiser establishes is that the object
        # is usable, and every rule after this one is unchanged.
        # `by_address` covers both forms that hand the resource to its own constructor:
        # a caller-allocated object (`yaml_parser_initialize(&p)`) and an out-parameter
        # constructor (`sqlite3_open(name, &db)`). Keying this on the caller-allocated case
        # alone left every sqlite3 plan blocked as use-before-create.
        inline_self_init = ({r.id for r in ir.resources if r.by_address}
                            & ({op.binds} - {""}))

        # A slot explicitly set to NULL is EMPTY: destroying it again frees nothing, and
        # mentioning it passes NULL rather than a dangling pointer. Applied before the
        # argument checks, because the op carrying the marker is the one that follows the
        # assignment.
        for _x in op.guarded_by:
            if _x.startswith("__cleared:"):
                _rid = _x.split(":", 1)[1]
                if state.get(_rid) == DEAD:
                    cleared.add(_rid)

        # A slot the call refilled is alive again, whatever happened to its previous value.
        for _x in op.guarded_by:
            if _x.startswith("__refills:"):
                _rid = _x.split(":", 1)[1]
                if _rid in state:
                    state[_rid] = ALIVE
                    born_arm[_rid] = _arm_of(op)
                    born_at[_rid] = op.id
                    dead_by.pop(_rid, None)

        for a in op.args:
            if a.source != SRC_RESOURCE or not a.ref:
                continue
            if a.ref in inline_self_init:
                continue
            if (a.ref not in _checked and a.ref in _created_by_call
                    and _storage_of.get(a.ref, "handle") == "handle"
                    and not _tests(_guard_of(op), _names_of.get(a.ref, []))):
                # INFO, NOT WARN, AND THE REASON IS A MEASUREMENT.
                #
                # This fires on 43 of 340 trusted lifts, 12%, and it cannot tell an
                # unchecked return from one that CANNOT FAIL. tidy-html5 calls
                # `fuzzer_get_tmpfile`, which aborts on every failure path and never
                # returns NULL, so the missing check there is correct -- and nothing short
                # of reading the callee could establish that. It also needs an allocation
                # failure to matter, which fuzzers do not inject by default.
                #
                # So it is advisory and explicitly NOT a finding source. The warning tier
                # is where upstream-reportable defects live and it stays clean.
                v.append(Violation("S1.UNCHECKED_ALLOCATION", INFO,
                                   f"{a.ref!r} is used by {op.api} without anything having "
                                   f"established it is non-NULL; an allocation failure "
                                   f"crashes the harness and the crash is attributed to "
                                   f"the library",
                                   where=op.id, principle="P1",
                                   fix=f"test {a.ref!r} after it is created, or return "
                                       f"early when it is NULL"))
                _checked.add(a.ref)   # report the FIRST unchecked use only
            if a.ref not in state:
                v.append(Violation("S1.UNKNOWN_RESOURCE", BLOCK,
                                   f"op {op.id} uses undeclared resource {a.ref!r}",
                                   where=op.id, principle="P1",
                                   fix=f"declare {a.ref!r} in resources[]"))
            elif state[a.ref] == UNBORN:
                v.append(Violation("S1.USE_BEFORE_CREATE", BLOCK,
                                   f"op {op.id} uses {a.ref!r} before anything creates it",
                                   where=op.id, principle="P1"))
            elif state[a.ref] == DEAD and a.ref in cleared:
                pass          # the slot is empty; this passes NULL, not a dangling pointer
            elif (state[a.ref] == DEAD
                  and dead_by.get(a.ref, "") != op.api
                  and (op.api in _RAW_FREE_NAMES or _CLEANUP_NAME.search(op.api))):
                # Only a RELEASE call gets this exemption. `magic_close(m);
                # magic_buffer(m, ..)` is a use-after-free and must keep firing -- the
                # first version of this test asked only whether the NAME differed, which
                # every ordinary use-after-free also satisfies, and it silenced three.
                # The second phase of a teardown names the resource it is releasing; that
                # is not a use-after-free. Reported once, as TWO_PHASE_TEARDOWN, when the
                # destroy is handled below.
                pass
            elif state[a.ref] == DEAD and _unreachable_from(
                    dead_arm.get(a.ref), dead_exits.get(a.ref, False), _arm_of(op)):
                # DESTROYED ON A PATH THIS ONE EXCLUDES. openvpn's fuzz_list.c is a state
                # machine: a `switch` inside a `for`, freeing the hash in one case and
                # iterating it in another. The cases never both run, so the free does not
                # reach the use -- and read as a flat list it was a use-after-free.
                pass
            elif state[a.ref] == DEAD:
                v.append(Violation("S1.USE_AFTER_DESTROY", BLOCK,
                                   f"op {op.id} uses {a.ref!r} after it was destroyed"
                                   f" (a use-after-free in the harness itself)",
                                   where=op.id, principle="P1",
                                   fix="move the destroy after the last use"))

        if op.binds:
            if op.binds not in state:
                v.append(Violation("S1.UNKNOWN_RESOURCE", BLOCK,
                                   f"op {op.id} binds undeclared resource {op.binds!r}",
                                   where=op.id, principle="P1"))
            elif (state[op.binds] == ALIVE and not _by_addr.get(op.binds)
                  # A CREATE ON A DEAD RESOURCE IS A NEW LIFETIME, NOT A DOUBLE CREATE.
                  # `pixa = pixaReadMem(..); pixaDestroy(&pixa); pixa = pixaReadMem(..);`
                  # leaks nothing -- the slot was empty when it was refilled. Only a create
                  # over a LIVE value loses that value. The test was `!= UNBORN`, which
                  # treats a released slot exactly like an occupied one, and leptonica's
                  # ccthin harness does this twice per loop iteration.
                  and not _exclusive(born_arm.get(op.binds), _arm_of(op))
                  and not _owned_by_a_released_arena(op.binds)
                  and not _is_a_null_fallback(op)):
                # A SLOT REFILLED FROM AN ARENA LEAKS NOTHING. pjsip's auth harness parses
                # twice into the same `msg`, both allocations taken from a pool that
                # `pjsip_endpt_release_pool` returns; the first value is not leaked because
                # nothing owned it individually. Ownership already knew this, and only the
                # end-of-harness leak check was consulting it.
                # TWO ASSIGNMENTS ON PATHS THAT NEVER BOTH RUN ARE NOT A LEAK. openvpn's
                # harness assigns `tmp` in several mutually exclusive switch cases and
                # frees it in each; read as a flat statement list that is a create, then
                # another create, with the first leaked. The arms say otherwise.
                # A CALLER-DECLARED SLOT IS ALIVE AND STILL GETS FILLED. `sqlite3 *db = 0;
                # sqlite3_open(":memory:", &db);` -- the storage exists from the
                # declaration AND the library writes the handle into it, and those are not
                # in conflict. Marking such slots alive without this exemption turned every
                # ordinary out-parameter into a DOUBLE_CREATE: the fleet's flagged count
                # went from 3 to 16 on a change meant to REMOVE false positives, which is
                # what caught it.
                v.append(Violation("S1.DOUBLE_CREATE", BLOCK,
                                   f"resource {op.binds!r} is created twice "
                                   f"(first at {born_at.get(op.binds)}, again at {op.id}); "
                                   f"the first is leaked",
                                   where=op.id, principle="P1"))
            else:
                state[op.binds] = ALIVE
                born_arm[op.binds] = _arm_of(op)
                born_at[op.binds] = op.id
            if api.role != ROLE_CREATE:
                v.append(Violation("S1.BIND_NON_CREATE", WARN,
                                   f"op {op.id} binds a resource but {api.symbol} is declared "
                                   f"role={api.role!r}, not {ROLE_CREATE!r}",
                                   where=op.id, principle="P2"))

        if op.targets:
            if op.targets not in state:
                v.append(Violation("S1.UNKNOWN_RESOURCE", BLOCK,
                                   f"op {op.id} destroys undeclared resource {op.targets!r}",
                                   where=op.id, principle="P1"))
            elif state[op.targets] == UNBORN:
                v.append(Violation("S1.DESTROY_BEFORE_CREATE", BLOCK,
                                   f"op {op.id} destroys {op.targets!r} before it exists",
                                   where=op.id, principle="P1"))
            elif state[op.targets] == DEAD and (op.targets in cleared
                                                or "__nulls_target" in op.guarded_by):
                # DESTROY-BY-ADDRESS NULLS THE SLOT. `pixaDestroy(&pixa)` sets the caller's
                # pointer to NULL and returns early when it is already NULL, so a second
                # call frees nothing -- leptonica's ccthin destroys inside a loop and once
                # more after it. Redundant, and worth saying, but not a double free.
                v.append(Violation("S1.REDUNDANT_DESTROY", INFO,
                                   f"{op.targets!r} is already released and "
                                   f"{op.api} takes its address, so this call is a no-op",
                                   where=op.id, principle="P1"))
            elif (state[op.targets] == DEAD
                  and dead_by.get(op.targets, "") != op.api
                  and (_CLEANUP_NAME.search(dead_by.get(op.targets, ""))
                       or op.api in _RAW_FREE_NAMES)):
                # TWO DIFFERENT RELEASE FUNCTIONS ARE A TEARDOWN; THE SAME ONE TWICE IS A
                # DOUBLE FREE.
                #
                # `kdc_free_lookaside(context)` frees a component OF the context and
                # `krb5_free_context(context)` frees the context, and telling "frees X"
                # from "frees part of X" apart needs the callee, which an audit of
                # third-party harnesses does not have. `IedConnection_close(con);
                # IedConnection_destroy(con);` is the same question in another spelling.
                #
                # So the distinguishing signal is the NAME: a genuine double free is
                # `free(p); free(p);` or the same destroy called twice, and that still
                # blocks. Two different functions is a sequence we cannot resolve, and it
                # is reported rather than asserted.
                # TWO-PHASE TEARDOWN, NOT A DOUBLE FREE. `lldpd_port_cleanup(port, 1);
                # free(port);` is the correct sequence: cleanup releases the members and
                # the caller releases the object. lldpd's four harnesses do exactly this,
                # and lldpd_port_cleanup does NOT free the port -- verified in
                # src/lldpd-structs.c -- while lldpd_chassis_cleanup DOES, which is why the
                # same harness frees the port and not the chassis.
                #
                # Reported at INFO rather than dropped. Without the callee we cannot prove
                # the cleanup did not also free, so this is a judgement the reader should
                # see rather than one the gate should make silently.
                v.append(Violation("S1.TWO_PHASE_TEARDOWN", INFO,
                                   f"{op.targets!r} is released in two phases: "
                                   f"{dead_by.get(op.targets)} then {op.api}; correct if "
                                   f"the cleanup frees members only",
                                   where=op.id, principle="P1"))
            elif (state[op.targets] == DEAD
                  and _unreachable_from(dead_arm.get(op.targets),
                                        dead_exits.get(op.targets, False),
                                        _arm_of(op))):
                # Two frees in mutually exclusive arms are one free, whichever path runs.
                state[op.targets] = DEAD
                dead_arm[op.targets] = _arm_of(op)
                dead_exits[op.targets] = _exits(op)
                dead_by[op.targets] = op.api
            elif state[op.targets] == DEAD:
                v.append(Violation("S1.DOUBLE_DESTROY", BLOCK,
                                   f"resource {op.targets!r} is destroyed twice; the second "
                                   f"is a double free attributable to the harness",
                                   where=op.id, principle="P1"))
            else:
                state[op.targets] = DEAD
                dead_arm[op.targets] = _arm_of(op)
                dead_exits[op.targets] = _exits(op)
                dead_by[op.targets] = op.api

    # STORAGE DECIDES WHETHER A LIVE RESOURCE IS A LEAK. Only a `handle` -- memory the
    # LIBRARY allocated and handed back -- can leak. An object the harness owns inline is
    # a stack variable whose destructor runs at scope exit, and reporting it demoted
    # woff2's real entry point (which constructs a sink) below a trivial size calculation
    # that constructs nothing: the warning count is part of the ranking, so a spurious
    # warning does not merely add noise, it picks the wrong harness.
    _owned = {r.id: (r.storage or "handle") for r in ir.resources}

    # A RESOURCE ALLOCATED FROM AN ARENA IS FREED WHEN THE ARENA IS.
    #
    # `apr_pool_create(&pool, NULL); p = apr_palloc(pool, n); ... apr_pool_destroy(pool);`
    # frees `p` without ever naming it. So does talloc, so do obstacks, and so does any
    # harness-local collector. S1 pairs each resource with a destroy that NAMES it, so
    # every arena allocation read as leaked -- and S1.LEAK fired on 67 of the 117 OSS-Fuzz
    # harnesses this engine can read, 57%, which is not a signal anyone can triage.
    #
    # The rule is derivable rather than a list of allocator names: a resource whose CREATE
    # op took another resource as an argument is owned by that resource, and if the owner
    # is destroyed, so is it. Transitive, because arenas nest.
    _owner: dict = {}
    for op in ir.sequence:
        if not op.binds:
            continue
        for a in op.args:
            if a.source == SRC_RESOURCE and a.ref != op.binds:
                _owner[op.binds] = a.ref
                break

    # A HARNESS-LOCAL COLLECTOR FREES IN BULK, UNDER ITS OWN NAME.
    #
    # openvpn's harnesses allocate through `gb_get_random_string()` and release everything
    # with `gb_cleanup()`; apache-httpd pairs `af_gb_init()` with `af_gb_cleanup()`. The
    # resource is never named at the free, so pairing by resource cannot see it -- and this
    # is the shape that made S1.LEAK unreadable in the first place.
    #
    # The link is the MODULE PREFIX: a creating function and a cleanup function that share
    # their first underscore-separated token belong to the same collector. Weaker evidence
    # than an argument, so it reports at INFO and never blocks.
    # The prefix alone is far too weak: `msg_unpack` and `msg_free_unpacked` share one
    # too, and keying on that suppressed leaks across every well-named C library -- caught
    # by the test pinning `if (x == NULL) free(x)` as a real defect, which stopped firing.
    #
    # What distinguishes a COLLECTOR is that it names no resource: `gb_cleanup()` and
    # `af_gb_cleanup()` take nothing, because their whole job is to free what the harness
    # can no longer name. A free that takes its target is ordinary pairing, not bulk.
    _bulk_prefixes = {op.api.split("_", 1)[0]
                      for op in ir.sequence
                      if "_" in op.api and _FREEISH_NAME.search(op.api)
                      and not op.targets
                      and not any(a.source == SRC_RESOURCE for a in op.args)}

    def _freed_in_bulk(rid: str) -> str:
        for op in ir.sequence:
            if op.binds == rid and "_" in op.api:
                pre = op.api.split("_", 1)[0]
                if pre in _bulk_prefixes:
                    return pre
        return ""

    def _freed_with_owner(rid: str, seen=None) -> bool:
        seen = seen or set()
        own = _owner.get(rid)
        if not own or own in seen:
            return False
        seen.add(own)
        return state.get(own) == DEAD or _freed_with_owner(own, seen)

    for rid, st in state.items():
        if st == ALIVE and _owned.get(rid, "handle") == "inline":
            continue
        if st == ALIVE and _freed_in_bulk(rid):
            v.append(Violation("S1.FREED_IN_BULK", INFO,
                               f"resource {rid!r} is allocated by a {_freed_in_bulk(rid)}_* "
                               f"function and the harness calls a {_freed_in_bulk(rid)}_* "
                               f"cleanup; it is released in bulk rather than by name",
                               where=rid, principle="P1"))
            continue
        if st == ALIVE and _freed_with_owner(rid):
            v.append(Violation("S1.FREED_WITH_OWNER", INFO,
                               f"resource {rid!r} was allocated from {_owner[rid]!r}, which "
                               f"is destroyed; it is released with its owner rather than "
                               f"by a destroy of its own",
                               where=rid, principle="P1"))
            continue
        if st == ALIVE:
            v.append(Violation("S1.LEAK", BLOCK if ir.knobs.detect_leaks else WARN,
                               f"resource {rid!r} is still alive when the harness returns; "
                               f"under LeakSanitizer every input reports a leak and real "
                               f"findings drown in it",
                               where=rid, principle="P1",
                               fix="add a destroy op, or disable leak detection deliberately "
                                   "and record that you did"))
        elif st == UNBORN:
            v.append(Violation("S1.UNUSED_RESOURCE", INFO,
                               f"resource {rid!r} is declared and never created",
                               where=rid, principle="P1"))

    return decide("S1", "lifetime: created once, destroyed once, never used after", v,
                  resources=len(ir.resources), ops=len(ir.sequence))


# ── S2 — contract ─────────────────────────────────────────────────────────────

# Pointer targets a fuzzer may legitimately fill with raw bytes. Everything else is a
# structured object the library will dereference field by field.
_BYTE_TARGETS = {"void", "char", "unsigned char", "signed char", "uint8_t", "int8_t",
                 "xmlChar", "byte", "u_char"}


# Library spellings of "a byte". Kept beside _BYTE_TARGETS rather than imported from the
# producer, because a gate must not depend on the thing it judges.
_BYTE_TYPEDEFS = frozenset({
    "Bytef", "Byte", "uch", "u8", "U8", "UInt8", "uint8", "guint8", "gchar",
    "xmlChar", "JOCTET", "png_byte", "Uint8", "uchar", "u_char",
})


def _points_to_bytes(type_name: str, resolved: str = "") -> bool:
    """A single pointer to a byte-sized type, and nothing else.

    The star count matters. `char **` is not a buffer of bytes — it is a pointer to a
    pointer, almost always an out-parameter the library writes (`sqlite3_exec`'s `errmsg`).
    Stripping every `*` before the comparison made `char **` look like `char *`, so fuzzer
    bytes were bound to it and the library would write through an address made of input.
    """
    t = re.sub(r"\b(const|volatile|struct|restrict|__restrict)\b", " ", type_name)
    if t.count("*") != 1:
        return False
    base = " ".join(t.replace("*", " ").split())
    # The IR may state what a typedef bottoms out in. `const l_uint8 *` is a byte buffer and
    # only leptonica's own header says so; without this the gate refuses the one correct
    # harness for pixReadMem. Still independent: the gate reads a fact RECORDED IN THE
    # ARTIFACT, which is printed and auditable, not a claim passed from the producer.
    if resolved and resolved in _BYTE_TARGETS:
        return True
    if base in _BYTE_TARGETS:
        return True
    # A library that typedefs its byte is still handing you bytes. zlib's `const Bytef *`
    # was read as a structured pointer, so S2 refused the only correct binding for
    # `uncompress2` — the gate blocking the fix rather than the mistake.
    return base in _BYTE_TYPEDEFS


_PATH_PARAM = re.compile(r"(?:^|_)(file|filename|fname|path|pathname|dir|dirname|uri|url)"
                         r"(?:$|_|name)", re.I)

_BYTE_POINTEES = ("char", "void", "unsigned char", "signed char", "uint8_t", "int8_t",
                  "u_char", "uchar", "byte", "BYTE", "guchar", "Bytef", "Byte")


def _byte_pointee(t) -> bool:
    """Whether a pointer type points at bytes, by spelling or through a typedef."""
    base = " ".join(re.sub(r"\b(const|volatile|struct|enum|union|restrict)\b", " ",
                           (t.resolved or t.name)).replace("*", " ").split())
    return base in _BYTE_POINTEES


def s2_contract(ir: HarnessIR) -> GateResult:
    """The API's stated requirements versus what the plan actually feeds it."""
    v: list[Violation] = []
    checked = 0

    # Type confusion: fuzzer bytes bound to a pointer the library will DEREFERENCE.
    #
    # Found in a proposed libyaml harness, which cast the input straight to a structured
    # type:
    #
    #     yaml_document_get_node((yaml_document_t *)hf_s_document, 0)
    #
    # That harness crashes on almost every input, and every crash is the harness's own
    # invalid pointer rather than a defect in the library. It is the single largest source
    # of false findings in the published literature, and it is decidable from the plan — no
    # compiler, no campaign, no crash triage required.
    for op in ir.sequence:
        api = ir.api_of(op)
        if api is None:
            continue
        for a in op.args:
            if a.source != SRC_INPUT:
                continue
            pd = ir.param_decl(api, a.param)
            if pd is None or "*" not in pd.type.name:
                continue
            checked += 1
            if not _points_to_bytes(pd.type.name, pd.type.resolved):
                v.append(Violation(
                    "S2.TYPE_CONFUSION", BLOCK,
                    f"op {op.id}: parameter {a.param!r} of {api.symbol} has type "
                    f"{pd.type.name!r}, and the plan fills it with raw fuzzer bytes. The "
                    f"library will dereference that as a real object, so EVERY crash is the "
                    f"harness's own invalid pointer and not a defect in the target.",
                    where=op.id, principle="P2",
                    fix=f"drive {api.symbol} through the API that BUILDS a "
                        f"{pd.type.name.replace('*','').strip()} from bytes, or bind "
                        f"{a.param!r} to a resource the plan constructs, or drop this "
                        f"entry point: it does not consume serialised input"))

    for op in ir.sequence:
        api = ir.api_of(op)
        if api is None:
            v.append(Violation("S2.UNKNOWN_API", BLOCK,
                               f"op {op.id} calls {op.api!r}, which is not declared in apis[]",
                               where=op.id, principle="P2"))
            continue

        by_param = {a.param: a for a in op.args}

        # every declared parameter must be supplied -- unless the function is variadic,
        # where the declared list is one call site's shape and another call legitimately
        # differs
        _var = bool(getattr(api, "variadic", False))
        for pd in api.params:
            if pd.name not in by_param and not _var:
                v.append(Violation("S2.MISSING_ARG", BLOCK,
                                   f"op {op.id} omits parameter {pd.name!r} of {api.symbol}",
                                   where=op.id, principle="P2"))
        for a in op.args:
            if ir.param_decl(api, a.param) is None and not _var:
                v.append(Violation("S2.UNKNOWN_PARAM", BLOCK,
                                   f"op {op.id} passes {a.param!r}, which {api.symbol} does "
                                   f"not declare", where=op.id, principle="P2"))
            if a.source not in SOURCES:
                v.append(Violation("S2.BAD_SOURCE", BLOCK,
                                   f"op {op.id} arg {a.param!r} has unknown source "
                                   f"{a.source!r}", where=op.id, principle="P2"))
            if a.source == SRC_INPUT and ir.slice_by_id(a.ref) is None:
                v.append(Violation("S2.UNKNOWN_SLICE", BLOCK,
                                   f"op {op.id} arg {a.param!r} references undeclared slice "
                                   f"{a.ref!r}", where=op.id, principle="P2"))

        # THE INPUT MUST NOT GO TO AN OUTPUT WHILE THE INPUT PARAMETER SITS UNUSED.
        #
        # `ZSTD_decompress(void *dst, size_t dstCapacity, const void *src, size_t srcSize)`
        # has two void* parameters and the FIRST is the output. A producer that took them
        # in declaration order bound the fuzzer's bytes to `dst` and passed `src` as NULL:
        # the harness decompressed nothing, wrote attacker bytes through a destination
        # pointer, and every gate here passed it. Coverage read 2.24% and looked like a
        # measurement rather than a broken harness.
        #
        # Deliberately narrow. Plenty of APIs take a non-const buffer they transform in
        # place, and this does not object to those. It fires only when the SAME call
        # declares a const byte pointer that nothing is bound to -- the library naming its
        # input, with the plan having chosen something else.
        _in_params = {a.param for a in op.args if a.source == SRC_INPUT}
        if _in_params:
            _const_free = [pd.name for pd in api.params
                           if pd.type.kind == "pointer" and pd.type.const
                           and _byte_pointee(pd.type) and not _PATH_PARAM.search(pd.name or "")
                           and pd.name not in _in_params]
            for _pn in sorted(_in_params):
                _pd = ir.param_decl(api, _pn)
                if _pd is None or _pd.type.kind != "pointer" or _pd.type.const:
                    continue
                if _const_free:
                    v.append(Violation(
                        "S2.INPUT_TO_OUTPUT", BLOCK,
                        f"op {op.id} binds the fuzzer's input to {_pn!r}, which "
                        f"{api.symbol} does not mark const, while {_const_free[0]!r} is a "
                        f"const buffer parameter nothing is bound to. The library names its "
                        f"input with const; writing attacker bytes through the output and "
                        f"leaving the input unset exercises nothing",
                        where=op.id, principle="P2",
                        fix=f"bind the input slice to {_const_free[0]!r} and give {_pn!r} "
                            f"a scratch buffer"))

        # ── the one that matters: NUL termination ──
        for pname in api.contract.nul_terminated:
            checked += 1
            a = by_param.get(pname)
            if a is None:
                continue
            if a.source == SRC_LITERAL:
                continue  # a C string literal is terminated by construction
            if a.source != SRC_INPUT:
                v.append(Violation("S2.CSTRING_SOURCE", WARN,
                                   f"op {op.id}: {api.symbol} requires {pname!r} to be "
                                   f"NUL-terminated but it comes from {a.source!r}; "
                                   f"termination cannot be checked here",
                                   where=op.id, principle="P2"))
                continue
            sl = ir.slice_by_id(a.ref)
            if sl is None:
                continue
            if not sl.is_nul_terminated:
                v.append(Violation(
                    "S2.CSTRING", BLOCK,
                    f"op {op.id}: {api.symbol} requires {pname!r} to be NUL-terminated, but "
                    f"slice {sl.id!r} is kind={sl.kind!r} and adds no terminator. The library "
                    f"will read past the end of EVERY input, so every input becomes a crash "
                    f"and every finding is the harness's own.",
                    where=op.id, principle="P2",
                    fix=f"set slice {sl.id!r} kind to 'cstring', or call the "
                        f"length-delimited variant of {api.symbol} instead"))

        # ── (ptr, len) pairs must agree ──
        for pair in api.contract.length_delimited:
            checked += 1
            if len(pair) != 2:
                v.append(Violation("S2.BAD_PAIR", BLOCK,
                                   f"{api.symbol}: length_delimited entry {pair!r} is not a "
                                   f"(pointer, length) pair", where=op.id, principle="P2"))
                continue
            pptr, plen = pair
            ap, al = by_param.get(pptr), by_param.get(plen)
            if ap is None or al is None:
                continue
            if ap.source == SRC_INPUT:
                if al.source != SRC_LENGTH_OF:
                    v.append(Violation(
                        "S2.LEN_SOURCE", BLOCK,
                        f"op {op.id}: {plen!r} must be the length of {pptr!r}, but it is "
                        f"sourced as {al.source!r}. A length that does not match its buffer "
                        f"is an out-of-bounds access the harness caused.",
                        where=op.id, principle="P2",
                        fix=f"set {plen!r} to source 'length_of' with ref {ap.ref!r}"))
                elif al.ref != ap.ref:
                    v.append(Violation(
                        "S2.LEN_MISMATCH", BLOCK,
                        f"op {op.id}: {plen!r} is the length of slice {al.ref!r} but {pptr!r} "
                        f"points at slice {ap.ref!r}. Mismatched pair.",
                        where=op.id, principle="P2"))
            if ap.source == SRC_INPUT:
                sl = ir.slice_by_id(ap.ref)
                if sl is not None and sl.is_nul_terminated:
                    v.append(Violation(
                        "S2.CSTRING_TO_LEN_API", INFO,
                        f"op {op.id}: slice {sl.id!r} is NUL-terminated but {api.symbol} takes "
                        f"an explicit length; the terminator is harmless here but the extra "
                        f"byte is never tested",
                        where=op.id, principle="P2"))

        # ── non-null ──
        for pname in api.contract.requires_nonnull:
            checked += 1
            a = by_param.get(pname)
            if a is None:
                continue
            if a.source == SRC_LITERAL and a.value in (None, 0, "NULL"):
                v.append(Violation("S2.NULL_ARG", BLOCK,
                                   f"op {op.id}: {api.symbol} requires {pname!r} to be "
                                   f"non-null and the plan passes NULL",
                                   where=op.id, principle="P2"))
            if a.source == SRC_RESOURCE and a.ref and a.ref not in op.guarded_by:
                producer = next((o for o in ir.sequence if o.binds == a.ref), None)
                if producer is not None:
                    papi = ir.api_of(producer)
                    if papi and papi.contract.error_return in ("null", "negative", "zero"):
                        v.append(Violation(
                            "S2.UNGUARDED_NONNULL", BLOCK,
                            f"op {op.id}: {api.symbol} requires {pname!r} non-null, and "
                            f"{a.ref!r} comes from {papi.symbol} which signals failure by "
                            f"returning {papi.contract.error_return!r}. Unguarded.",
                            where=op.id, principle="P1",
                            fix=f"add {a.ref!r} to guarded_by on op {op.id}"))

        # ── ownership ──
        for pname in api.contract.transfers_ownership:
            a = by_param.get(pname)
            if a is None or a.source != SRC_RESOURCE or not a.ref:
                continue
            later = ir.sequence[ir.sequence.index(op) + 1:]
            if any(o.targets == a.ref for o in later):
                v.append(Violation(
                    "S2.DOUBLE_FREE_OWNERSHIP", BLOCK,
                    f"op {op.id}: {api.symbol} takes ownership of {a.ref!r}, but a later op "
                    f"destroys it as well. That is a double free the harness performed.",
                    where=op.id, principle="P2",
                    fix=f"remove the later destroy of {a.ref!r}"))

    return decide("S2", "contract: NUL-termination, (ptr,len) pairs, ownership, non-null", v,
                  contract_clauses_checked=checked)


# ── S3 — ordering ─────────────────────────────────────────────────────────────

def s3_ordering(ir: HarnessIR) -> GateResult:
    """Roles must appear in a legal order, and the sequence must actually do something."""
    v: list[Violation] = []
    seen_roles: list[str] = []

    for op in ir.sequence:
        api = ir.api_of(op)
        if api is None:
            continue
        if api.role not in ROLES:
            v.append(Violation("S3.BAD_ROLE", BLOCK,
                               f"{api.symbol} declares unknown role {api.role!r}",
                               where=op.id, principle="P2"))
            continue
        seen_roles.append(api.role)
        # A HEDGED DESTROY IS NOT A BROKEN ONE. The api entry is keyed by SYMBOL, so a
        # library's free function that appears both at top level and inside a branch gets
        # ONE role -- destroy, from the unconditional call. The lifter deliberately
        # withholds `targets` on the branch copy, because marking the resource dead there
        # would report every later use as a certain use-after-free on a path that may never
        # run. Those two correct decisions met and produced a third, wrong one:
        # "destroy names no resource" against openvpn's harnesses, which free correctly on
        # every exit path. The op records that it is guarded; the gate reads that instead of
        # judging a claim the lifter did not make. Keyed on the lifter's OWN marker,
        # `__branch`, not on "is guarded at all": exempting every guarded destroy stopped
        # the gate intercepting a known defect class, which its own test caught
        # immediately. A hedge is narrow or it is a hole.
        # ...AND NOT WHEN THE CALL NAMES NO RESOURCE AT ALL.
        #
        # An API's role is decided once for the whole harness, so a local wrapper like
        # libsrtp's `fuzz_free(void *ptr)` becomes destroy-role the moment ONE call site
        # passes it a tracked resource -- and every other call, freeing a plain buffer the
        # lift never modelled, then read as "a destroy that names nothing".
        #
        # A destroy-role call carrying no resource argument is releasing memory outside the
        # lift's model. That is a gap in what we track, not a defect in the harness, and
        # the earlier hedge (skip when guarded) did not cover it.
        if (api.role == ROLE_DESTROY and not op.targets
                and any(a.source == SRC_RESOURCE and a.ref for a in op.args)
                and not any(x.startswith("__branch") for x in op.guarded_by)):
            v.append(Violation("S3.DESTROY_NO_TARGET", BLOCK,
                               f"op {op.id} calls destroy-role {api.symbol} without naming "
                               f"the resource it releases", where=op.id, principle="P2"))
        if api.role == ROLE_CREATE and not op.binds:
            v.append(Violation("S3.CREATE_NO_BIND", WARN,
                               f"op {op.id} calls create-role {api.symbol} but binds nothing; "
                               f"the returned resource is dropped on the floor",
                               where=op.id, principle="P1"))

    if not ir.sequence:
        v.append(Violation("S3.EMPTY", BLOCK, "the plan has no ops: this harness tests nothing",
                           principle="P4"))
    elif (not any(r in (ROLE_CONSUME, ROLE_CREATE) for r in seen_roles)
          and not any(a.source in (SRC_INPUT, SRC_SCRATCH, SRC_SCRATCH_ADDR)
                      for op in ir.sequence for a in op.args)):
        v.append(Violation("S3.NO_WORK", BLOCK,
                           "no op consumes input or creates a resource; the harness performs "
                           "no work on the target", principle="P4"))

    return decide("S3", "ordering: create before use before destroy", v,
                  roles=seen_roles)


# ── S4 — boundary ─────────────────────────────────────────────────────────────

def s4_boundary(ir: HarnessIR) -> GateResult:
    """Exercise the public interface. A harness that reaches past the library's own
    validation finds bugs no attacker can reach, and every one is a wasted report."""
    v: list[Violation] = []
    public = set(ir.target.public_headers)

    for sym, api in ir.apis.items():
        if api.contract.internal_only:
            v.append(Violation("S4.INTERNAL", BLOCK,
                               f"{sym} is marked internal-only. Calling it bypasses the "
                               f"library's own validation, so any crash it produces is not "
                               f"reachable by an attacker through the public API.",
                               where=sym, principle="P3",
                               fix="call the public entry point that wraps it"))
        elif public and api.header not in public:
            v.append(Violation("S4.NON_PUBLIC_HEADER", WARN,
                               f"{sym} is declared in {api.header!r}, which is not listed in "
                               f"target.public_headers; it may not be part of the supported "
                               f"surface", where=sym, principle="P3"))

    if not public:
        v.append(Violation("S4.NO_PUBLIC_SET", INFO,
                           "target.public_headers is empty, so the boundary check could not "
                           "discriminate. Populate it to make this gate meaningful.",
                           principle="P3"))

    return decide("S4", "boundary: public interface only", v,
                  apis=len(ir.apis), public_headers=sorted(public))


# ── S5 — input flow ───────────────────────────────────────────────────────────

def _input_reaches_via_scratch(ir: HarnessIR) -> bool:
    """A streaming API takes the input through a CURSOR, not as an argument.

    `BrotliDecoderDecompressStream(state, &avail_in, &next_in, ...)` never receives the
    slice directly: `next_in` is a pointer variable initialised FROM it. S5 counted no
    op as receiving input and refused a correctly-bound plan — the gate right about its
    own rule and wrong about the world.
    """
    from ..ir import SRC_SCRATCH_ADDR
    slice_ids = {s.id for s in ir.slices}
    fed = {sc.id for sc in ir.scratch if sc.init_from in slice_ids}
    return any(a.source == SRC_SCRATCH_ADDR and a.ref in fed
               for op in ir.sequence for a in op.args)


def s5_input_flow(ir: HarnessIR) -> GateResult:
    """The fuzzer's bytes must actually reach the target, and every declared slice must be
    used. An unused slice is input the fuzzer spends effort mutating for no effect."""
    v: list[Violation] = []
    used: set[str] = set()
    input_reaching_ops = 0

    for op in ir.sequence:
        touches_input = False
        for a in op.args:
            if a.source in (SRC_INPUT, SRC_LENGTH_OF) and a.ref:
                used.add(a.ref)
                touches_input = True
        if touches_input:
            input_reaching_ops += 1

    for s in ir.slices:
        if s.id not in used:
            v.append(Violation("S5.UNUSED_SLICE", WARN,
                               f"slice {s.id!r} is declared and never passed to any op; the "
                               f"fuzzer will mutate bytes that change nothing",
                               where=s.id, principle="P4"))
        if s.kind not in SLICE_KINDS:
            v.append(Violation("S5.BAD_SLICE_KIND", BLOCK,
                               f"slice {s.id!r} has unknown kind {s.kind!r}",
                               where=s.id, principle="P4"))

    remainders = [s.id for s in ir.slices if s.remainder]
    if len(remainders) > 1:
        v.append(Violation("S5.MULTIPLE_REMAINDERS", BLOCK,
                           f"slices {remainders} all claim the remainder of the input; at most "
                           f"one may", principle="P4"))

    if not ir.slices:
        v.append(Violation("S5.NO_INPUT", BLOCK,
                           "the plan declares no input slices: nothing the fuzzer produces "
                           "reaches the target", principle="P4"))
    elif input_reaching_ops == 0 and not _input_reaches_via_scratch(ir):
        v.append(Violation("S5.INPUT_NOT_CONSUMED", BLOCK,
                           "no op receives fuzzer input; the harness runs a fixed program and "
                           "the campaign cannot find anything", principle="P4"))

    return decide("S5", "input flow: the fuzzer's bytes reach the target", v,
                  slices=len(ir.slices), used_slices=sorted(used),
                  input_reaching_ops=input_reaching_ops)


# ── S6 — error handling ───────────────────────────────────────────────────────

def s6_error_handling(ir: HarnessIR) -> GateResult:
    """A failure return that is not checked becomes a null dereference in the harness,
    reported against the library."""
    v: list[Violation] = []
    checked = 0

    for i, op in enumerate(ir.sequence):
        api = ir.api_of(op)
        if api is None or not op.binds:
            continue
        er = api.contract.error_return
        if er == "none":
            continue
        # A CALLER-OWNED STRUCT EXISTS WHETHER OR NOT THE CALL SUCCEEDED.
        #
        # This gate's claim is that the harness "dereferences the failure value", and that
        # can only happen when the resource's EXISTENCE depends on the call: a handle the
        # library allocates, or an out-parameter it fills with a pointer. An inline struct
        # the harness declared on its own stack is there either way, so using it after a
        # failed call reads stale-but-valid memory -- wrong results, not a crash.
        #
        # http-parser's fuzz_url.c is the case: `struct http_parser_url u;` on the stack,
        # http_parser_url_init(&u) returning void, and http_parser_parse_url returning int.
        # The gate BLOCKED a correct production harness on a mechanism that cannot occur.
        _res = next((r for r in ir.resources if r.id == op.binds), None)
        if _res is not None and _res.storage == "inline":
            continue
        checked += 1
        consumers = [o for o in ir.sequence[i + 1:]
                     if any(a.source == SRC_RESOURCE and a.ref == op.binds for a in o.args)
                     or o.targets == op.binds]
        for c in consumers:
            capi = ir.api_of(c)
            tolerant = bool(capi and capi.role == ROLE_DESTROY
                            and op.binds not in capi.contract.requires_nonnull)
            if op.binds in c.guarded_by or tolerant:
                continue
            v.append(Violation(
                "S6.UNCHECKED_ERROR", BLOCK,
                f"op {op.id} ({api.symbol}) signals failure by returning {er!r}, and op "
                f"{c.id} uses {op.binds!r} without a guard. On a rejected input the harness "
                f"dereferences the failure value and reports its own crash.",
                where=c.id, principle="P1",
                fix=f"add {op.binds!r} to guarded_by on op {c.id}"))

    return decide("S6", "error handling: failure returns are checked before use", v,
                  error_returning_ops=checked)


# ── driver ────────────────────────────────────────────────────────────────────

_GATES = {
    "S1": s1_lifetime,
    "S2": s2_contract,
    "S3": s3_ordering,
    "S4": s4_boundary,
    "S5": s5_input_flow,
    "S6": s6_error_handling,
}


# `apr_pool_terminate()` ends the whole pool subsystem and releases every pool with it,
# which is why apache-httpd's harness needs no per-pool destroy. "terminate" and "shutdown"
# are cleanup verbs a collector uses and a per-resource free does not.
# PHASE ONE: releases what the object HOLDS, without freeing the object.
# `lldpd_port_cleanup(port, 1)`, `IedConnection_close(con)`, `x_stop()`, `x_disconnect()`.
_RELEASE_VERBS = {"cleanup", "close", "stop", "fini", "deinit", "reset", "disconnect",
                  "shutdown", "flush", "end"}
# PHASE TWO: frees the object itself.
_DESTROY_VERBS = {"free", "destroy", "delete", "del", "dispose", "release", "unref",
                  "discard"}


def _has_verb(fn: str, verbs: set) -> bool:
    from ..lift.c_harness import _name_segments
    return any(seg in verbs for seg in _name_segments(fn))


class _CleanupName:
    """Phase one of a teardown: it must be a release verb and NOT itself a destroy, or
    `x_destroy` would count as its own first phase and mask a genuine double free."""

    @staticmethod
    def search(fn: str):
        return _has_verb(fn, _RELEASE_VERBS) and not _has_verb(fn, _DESTROY_VERBS)


_CLEANUP_NAME = _CleanupName()


class _RawFreeNames:
    def __contains__(self, fn: str):
        return _has_verb(fn, _DESTROY_VERBS)


_RAW_FREE_NAMES = _RawFreeNames()

def _FREEISH_NAME_search(fn: str):
    """Shares the lifter's vocabulary and its segment rule, rather than keeping a second
    copy that can drift. The substring form matched "end" inside "send"; a bulk-collector
    check would have matched "fini" inside "definition" the same way."""
    from ..lift.c_harness import _FREE_ISH
    return _FREE_ISH.search(fn)


class _FreeishName:
    search = staticmethod(_FREEISH_NAME_search)


_FREEISH_NAME = _FreeishName()


def run_static_gates(ir: HarnessIR, only: tuple = ALL_STATIC) -> list[GateResult]:
    results = [_GATES[g](ir) for g in only if g in _GATES]
    if ir.raw_blocks:
        ids = [b.id for b in ir.raw_blocks]
        r = passed("S0", "schema coverage: how much of this plan is certifiable")
        r.violations = [Violation(
            "S0.RAW_BLOCK", WARN,
            f"{len(ids)} raw block(s) {ids} contain verbatim C the schema does not model. "
            f"Nothing inside them is certified by any static gate.",
            principle="P1",
            fix="express the block in IR, or accept it as an uncertified region on the "
                "certificate")]
        results.insert(0, r)
    return results
