"""Pin the portable coverage-guided driver used where libFuzzer's runtime is absent."""
import shutil, subprocess
import pytest
from hforge.emit import winfuzz


def test_driver_has_the_pieces():
    src = winfuzz.driver_source()
    assert "__sanitizer_cov_trace_pc(" in src      # edge feedback, no guard sections
    assert "LLVMFuzzerTestOneInput" in src          # drives the same harness entry
    assert "__except" in src                        # SEH crash capture on Windows
    assert "-dict=" not in src or "dict_load" in src


def test_build_commands_shape():
    cmds = winfuzz.build_commands("harness.c", ["impl.c"], "fuzz.exe",
                                  includes=("inc",), defines=("HAVE_CONFIG_H",))
    # target + harness compiled with coverage; driver without; final link skips ubsan runtime
    assert any("-fsanitize-coverage=trace-pc" in c and "impl.c" in c for c in cmds)
    assert any("hf_winfuzz.o" in c and "-c" in c and
               "-fsanitize-coverage=trace-pc" not in c for c in cmds)
    assert any("/nodefaultlib:clang_rt.ubsan_standalone.lib" in c for c in cmds)


@pytest.mark.skipif(not shutil.which("clang"), reason="clang not installed")
def test_driver_compiles(tmp_path):
    src = tmp_path / "d.c"; src.write_text(winfuzz.driver_source())
    r = subprocess.run(["clang", "-fsyntax-only", "-w", str(src)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
