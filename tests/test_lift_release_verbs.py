"""Pinned behaviour of the lifter's release-verb reading, found on jansson's own tests.

Each test here is a case that produced a confident wrong answer before it was fixed. They are
pinned so the answer cannot quietly revert.
"""
from pathlib import Path

from hforge.lift.c_harness import lift


def _lift(tmp_path: Path, body: str):
    src = tmp_path / "h.c"
    src.write_text(
        "#include <stdint.h>\n#include <stddef.h>\n"
        "typedef struct json_t json_t;\n"
        "json_t *json_loads(const char *s, size_t f, void *e);\n"
        "void json_decref(json_t *j);\n"
        "int json_object_del(json_t *o, const char *key);\n"
        "int json_object_size(json_t *o);\n"
        "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
        + body + "\n    return 0;\n}\n")
    return lift(str(src), target_name="t")


def test_decref_is_a_release_so_recreating_into_the_same_variable_is_not_a_double_create(tmp_path):
    # json_decref lifted as a QUERY: S1 never saw the resource die, and the second json_loads
    # read as re-creating a live resource -- 114 DOUBLE_CREATE violations on jansson's suite.
    l = _lift(tmp_path, """
    json_t *j = json_loads((const char *)data, 0, 0);
    json_decref(j);
    j = json_loads((const char *)data, 0, 0);
    json_decref(j);""")
    decrefs = [o for o in l.ir.sequence if o.api == "json_decref"]
    assert decrefs, "json_decref was not lifted at all"
    assert all(l.ir.apis[o.api].role == "destroy" for o in decrefs)
    assert all(o.targets == "r_j" for o in decrefs)


def test_a_release_verb_with_a_string_literal_argument_is_a_keyed_removal_not_a_destroy(tmp_path):
    # json_object_del(obj, "key") removes ONE KEY. "del" is a release verb, so it read as
    # destroying obj and the following json_object_size was a use-after-free. strip_noise
    # blanks the literal to whitespace and _split_args drops the empty slot, so the guard has
    # to read the raw text: a comma with nothing after it is the mark a literal leaves.
    l = _lift(tmp_path, """
    json_t *obj = json_loads((const char *)data, 0, 0);
    json_object_del(obj, "key");
    json_object_size(obj);
    json_decref(obj);""")
    dels = [o for o in l.ir.sequence if o.api == "json_object_del"]
    assert dels, "json_object_del was not lifted at all"
    assert all(l.ir.apis[o.api].role != "destroy" for o in dels)
    assert all(o.targets == "" for o in dels)
