"""Pin the closed-binary track: command construction, result parsing, NOT_RUN contract."""
from hforge import closed


def test_litecov_cmd():
    c = closed.litecov_cmd("litecov", "bin", ["m1.dylib", "m2.dylib"], "cov.txt",
                           ["-lint", "in.dat"])
    assert c[0] == "litecov"
    assert c.count("-instrument_module") == 2
    assert "m1.dylib" in c and "m2.dylib" in c
    assert "-coverage_file" in c and "cov.txt" in c
    assert c[c.index("--") + 1] == "bin"          # target after the --
    assert c[-2:] == ["-lint", "in.dat"]


def test_jackalope_cmd_file_delivery():
    c = closed.jackalope_cmd("fuzzer", "bin", ["libx.1.2.dylib"], "seeds", "out",
                             ["@@", "-o", "/dev/null"], timeout_ms=1500)
    assert "-delivery" in c and c[c.index("-delivery") + 1] == "file"
    assert c[c.index("-t") + 1] == "1500"
    assert "libx.1.2.dylib" in c
    assert c[c.index("--") + 1] == "bin"
    assert "@@" in c                               # input placeholder preserved for jackalope


def test_jackalope_persist_mode():
    c = closed.jackalope_cmd("fuzzer", "bin", ["m"], "s", "o", ["@@"],
                             persist=True, target_method="fuzz", nargs=1)
    assert "-persist" in c and "-loop" in c
    assert "-target_method" in c and c[c.index("-target_method") + 1] == "fuzz"


def test_sub_input():
    assert closed._sub_input(["@@", "-o", "x"], "/tmp/i") == ["/tmp/i", "-o", "x"]


def test_parse_jackalope():
    out = ("Unique samples: 3 (0 discarded)\nCrashes: 0 (0 unique)\nHangs: 0\n"
           "Unique samples: 9 (0 discarded)\nCrashes: 2 (1 unique)\nHangs: 1\n")
    s = closed.parse_jackalope(out)
    assert s == {"unique_samples": 9, "crashes": 2, "hangs": 1}   # takes the last line


def test_coverage_once_missing_tool_is_minus_one():
    # a litecov path that does not exist -> the target never runs -> -1 (NOT a crash/finding)
    n = closed.coverage_once("bin", ["m"], __file__, litecov="/no/such/litecov")
    assert n == -1


def test_campaign_missing_tool_is_not_run(tmp_path):
    r = closed.campaign("bin", ["m"], str(tmp_path), str(tmp_path / "out"),
                        jackalope="/no/such/fuzzer")
    assert r.ran is False and "could not launch" in r.note


def test_toolchain_declares_closed_tools():
    from hforge import toolchain as tc
    names = [t.name for t in tc.inventory().tools]
    assert "litecov" in names and "jackalope" in names
