"""Pin seed provisioning: the generator ships a ready-to-fuzz corpus with every harness."""
from pathlib import Path
from hforge import seeds


def test_detect_formats_from_name_and_symbols():
    assert set(seeds.detect_formats("stb_image", ["stb_image.h"],
                                    ["stbi_load_from_memory"])) >= {"png", "jpeg", "gif", "bmp"}
    assert seeds.detect_formats("libwebp", ["webp/decode.h"], ["WebPDecodeRGBA"]) == ["webp"]
    assert seeds.detect_formats("cjson", ["cJSON.h"], ["cJSON_Parse"]) == ["json"]


def test_synth_seeds_carry_the_format_signature():
    assert seeds.SYNTH["png"]["a.png"].startswith(b"\x89PNG\r\n\x1a\n")
    assert seeds.SYNTH["gif"]["a.gif"].startswith(b"GIF89a")
    assert seeds.SYNTH["bmp"]["a.bmp"].startswith(b"BM")
    assert seeds.SYNTH["webp"]["a.webp"][:4] == b"RIFF" and b"WEBP" in seeds.SYNTH["webp"]["a.webp"]
    assert seeds.SYNTH["json"]["a.json"].strip()[:1] in (b"{", b"[")


def test_mine_skips_source_prefers_format(tmp_path):
    (tmp_path / "src").mkdir(); (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "a.c").write_text("int main(){}")      # source: never a seed
    (tmp_path / "tests" / "img.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00")
    (tmp_path / "stray.dat").write_bytes(b"\x01\x02\x03\x04")
    chosen = seeds.mine([str(tmp_path)], formats=(".png",))
    names = [p.name for p in chosen]
    assert "img.png" in names and "a.c" not in names          # png preferred, source excluded
    assert chosen[0].suffix == ".png"                         # format match ranks first


def test_provision_writes_mined_and_synth(tmp_path):
    repo = tmp_path / "repo"; (repo / "tests").mkdir(parents=True)
    (repo / "tests" / "x.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 20)
    dest = tmp_path / "out.seeds"
    rep = seeds.provision(dest, roots=[str(repo)], name="pnglib",
                          headers=["png.h"], symbols=["png_read"])
    assert rep["total"] >= 2 and rep["synthesised"] >= 1       # synth + at least the mined png
    files = list(dest.iterdir())
    assert any(f.name.startswith("synth_") for f in files)
    assert any(f.name.startswith("mined_") for f in files)


def test_provision_unknown_format_has_generic_fallback(tmp_path):
    rep = seeds.provision(tmp_path / "s", roots=[], name="mystery", headers=[], symbols=[])
    assert rep["synthesised"] >= 1                              # json/xml/png fallback, never empty
