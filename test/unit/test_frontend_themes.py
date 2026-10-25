import importlib.util
import re
from pathlib import Path

FRONTEND = Path(__file__).resolve().parents[2] / "drakrun" / "web" / "frontend"


def _generator():
    spec = importlib.util.spec_from_file_location("gen_themes", FRONTEND / "tools" / "gen_themes.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_palette_meets_its_contrast_targets():
    gen = _generator()
    for name, (_, _, modes) in gen.SCHEMES.items():
        assert set(modes) == {"light", "dark"}, name
        for mode, palette in modes.items():
            for what, fg, bg, minimum in gen.checks(palette):
                assert gen.contrast(fg, bg) >= minimum, f"{name}/{mode} {what}"


def test_generated_css_is_current_and_matches_the_picker():
    gen = _generator()
    css = (FRONTEND / "src" / "themes.css").read_text()
    for name, (_, _, modes) in gen.SCHEMES.items():
        for mode, palette in modes.items():
            assert f'[data-chimera-scheme="{name}"][data-bs-theme="{mode}"]' in css
            assert f"--chimera-canvas: {palette['canvas']};" in css
    picker = (FRONTEND / "src" / "themes.js").read_text()
    assert re.findall(r'id: "([a-z]+)"', picker) == list(gen.SCHEMES)


def test_theme_css_uses_only_semantic_tokens():
    css = (FRONTEND / "src" / "chimera-theme.css").read_text()
    assert "--chimera-base" not in css
