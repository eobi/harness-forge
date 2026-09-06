"""Pinned behaviour of the composer: rebinding by declared type, and freeing what it binds."""
from types import SimpleNamespace

from hforge.ir import Api, Arg, Contract, HarnessIR, InputSlice, Knobs, Op, ParamDecl, Resource, Target, TypeRef
from hforge.producers.compose import compose


def _api(sym, role, params, ret):
    return Api(symbol=sym, header="j.h", role=role,
               params=[ParamDecl(n, TypeRef(t, "pointer" if "*" in t else "scalar")) for t, n in params],
               returns=TypeRef(ret, "pointer" if "*" in ret else "scalar"), contract=Contract())


def _decl(name, params, ret):
    return SimpleNamespace(name=name, params=params, ret=ret)


def _plans():
    decls = {
        "json_loads": _decl("json_loads", [("const char *", "s"), ("size_t", "f"), ("void *", "e")], "json_t *"),
        "json_decref": _decl("json_decref", [("json_t *", "j")], "void"),
        "json_dumps": _decl("json_dumps", [("const json_t *", "json"), ("size_t", "flags")], "char *"),
    }
    apis = {k: _api(k, r, decls[k].params, decls[k].ret)
            for k, r in (("json_loads", "create"), ("json_decref", "destroy"), ("json_dumps", "query"))}
    a = HarnessIR(name="A", target=Target(name="j"), apis=dict(apis),
                  slices=[InputSlice("s_seam", "cstring", remainder=True, min_len=1)],
                  resources=[Resource("r_json", TypeRef("json_t *", "pointer"))],
                  sequence=[Op("o0", "json_loads", [Arg("s", "input", "s_seam"), Arg("f", "literal", value=0),
                                                    Arg("e", "literal", value=0)], binds="r_json"),
                            Op("o1", "json_decref", [Arg("j", "resource", "r_json")], targets="r_json")],
                  knobs=Knobs(), platforms=["linux-x86_64-glibc"], producer="test_lift")
    b = HarnessIR(name="B", target=Target(name="j"), apis=dict(apis), slices=[],
                  resources=[Resource("r_obj", TypeRef("json_t *", "pointer"))],
                  sequence=[Op("o0", "json_dumps", [Arg("json", "resource", "r_obj"), Arg("flags", "literal", value=0)])],
                  knobs=Knobs(), platforms=["linux-x86_64-glibc"], producer="test_lift")
    return a, b, decls


def test_serialise_call_is_rebound_to_the_parsed_value_and_inserted_before_its_destroy():
    a, b, decls = _plans()
    plan, rec = compose(a, b, decls)
    assert plan is not None, rec
    apis_in_order = [o.api for o in plan.sequence]
    assert apis_in_order.index("json_dumps") < apis_in_order.index("json_decref")
    dumps = next(o for o in plan.sequence if o.api == "json_dumps")
    assert dumps.args[0].source == "resource" and dumps.args[0].ref == "r_json"
    assert rec["rebound_param"] == "json"


def test_a_pointer_returned_by_the_taken_call_is_bound_and_freed():
    # json_dumps returns a malloc'd char*. Left unbound, the composed harness leaked it on
    # every input and LeakSanitizer would have reported the harness itself.
    a, b, decls = _plans()
    plan, _ = compose(a, b, decls)
    dumps = next(o for o in plan.sequence if o.api == "json_dumps")
    assert dumps.binds, "the dumps result was not bound"
    frees = [o for o in plan.sequence if o.api == "free" and o.targets == dumps.binds]
    assert frees, "nothing frees the dumps result"
    assert plan.sequence.index(frees[0]) > plan.sequence.index(dumps)


def test_composition_refuses_when_a_already_enters_the_subsystem():
    a, b, decls = _plans()
    a2 = HarnessIR(**{**a.__dict__, "sequence": a.sequence + [Op("o2", "json_dumps",
                       [Arg("json", "resource", "r_json"), Arg("flags", "literal", value=0)])]})
    plan, rec = compose(a2, b, decls)
    assert plan is None and "already enters" in rec["why_not"]


def test_a_resource_produced_through_an_out_parameter_after_the_seam_is_matched():
    # libyaml's seam call returns void; the document arrives later through an out-parameter
    # of yaml_parser_load(&parser, &document). Matching only the seam call's return type
    # composed nothing. Every resource bound at or after the seam is a candidate, typed from
    # the declared parameter when the call fills an out-parameter.
    decls = {
        "yaml_parser_set_input_string": _decl("yaml_parser_set_input_string",
            [("yaml_parser_t *", "parser"), ("const unsigned char *", "input"), ("size_t", "size")], "void"),
        "yaml_parser_load": _decl("yaml_parser_load",
            [("yaml_parser_t *", "parser"), ("yaml_document_t *", "document")], "int"),
        "yaml_document_delete": _decl("yaml_document_delete", [("yaml_document_t *", "document")], "void"),
        "yaml_emitter_dump": _decl("yaml_emitter_dump",
            [("yaml_emitter_t *", "emitter"), ("yaml_document_t *", "document")], "int"),
    }
    apis = {k: _api(k, r, decls[k].params, decls[k].ret) for k, r in (
        ("yaml_parser_set_input_string", "consume"), ("yaml_parser_load", "create"),
        ("yaml_document_delete", "destroy"), ("yaml_emitter_dump", "query"))}
    a = HarnessIR(name="A", target=Target(name="y"), apis=dict(apis),
                  slices=[InputSlice("s_seam", "bytes", remainder=True, min_len=1)],
                  resources=[Resource("r_parser", TypeRef("yaml_parser_t", "struct"), storage="inline"),
                             Resource("r_doc", TypeRef("yaml_document_t", "struct"), storage="inline")],
                  sequence=[Op("o0", "yaml_parser_set_input_string",
                               [Arg("parser", "resource", "r_parser"), Arg("input", "input", "s_seam"),
                                Arg("size", "length_of", "s_seam")]),
                            Op("o1", "yaml_parser_load",
                               [Arg("parser", "resource", "r_parser"), Arg("document", "resource", "r_doc")],
                               binds="r_doc"),
                            Op("o2", "yaml_document_delete", [Arg("document", "resource", "r_doc")],
                               targets="r_doc")],
                  knobs=Knobs(), platforms=["linux-x86_64-glibc"], producer="test_lift")
    b = HarnessIR(name="B", target=Target(name="y"), apis=dict(apis), slices=[],
                  resources=[Resource("r_em", TypeRef("yaml_emitter_t", "struct"), storage="inline"),
                             Resource("r_bdoc", TypeRef("yaml_document_t", "struct"), storage="inline")],
                  sequence=[Op("o0", "yaml_emitter_dump",
                               [Arg("emitter", "resource", "r_em"), Arg("document", "resource", "r_bdoc")])],
                  knobs=Knobs(), platforms=["linux-x86_64-glibc"], producer="test_lift")
    plan, rec = compose(a, b, decls)
    assert plan is not None, rec
    dump = next(o for o in plan.sequence if o.api == "yaml_emitter_dump")
    assert dump.args[1].ref == "r_doc", "the emitter's document was not rebound to the parsed one"
    assert rec["rebound_resource"] == "r_doc"
    order = [o.api for o in plan.sequence]
    assert order.index("yaml_emitter_dump") < order.index("yaml_document_delete")
