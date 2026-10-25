#!/usr/bin/env python3
"""Generate src/themes.css: every colour scheme in a light and a dark version, as CSS custom properties.

    python3 tools/gen_themes.py            write src/themes.css (fails if a contrast check fails)
    python3 tools/gen_themes.py --check    only run the contrast checks

chimera-theme.css only uses the semantic tokens defined here (--chimera-canvas, --chimera-text, ...), so a scheme
is a palette and nothing else. Each palette is checked against WCAG 2.2: body text and headings 7:1 (AAA) on
the canvas and on cards, secondary text and every status "ink" (coloured words, also on its own tinted chip)
4.5:1, and button text 4.5:1. src/themes.js lists the same scheme names for the picker.
"""

import sys
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "src" / "themes.css"

# name: (label, note, {mode: palette})
SCHEMES = {
    "solarized": (
        "Solarized",
        "The CHIMERA default: warm, low-glare paper and a deep teal shell.",
        {
            "light": dict(
                shell="#002b36", shell_raised="#073642", shell_deep="#002b36", shell_text="#a7b3b3",
                shell_muted="#93a1a1", shell_strong="#fdf6e3",
                canvas="#eee8d5", surface="#fdf6e3", surface2="#eee8d5", surface3="#e3dcc6",
                border="#ded7c2", border_strong="#cdc5ad",
                heading="#073642", text="#3a4a50", muted="#56686e", strong="#002b36",
                accent="#268bd2", accent_ink="#1a6294", on_accent="#fdf6e3",
                red="#dc322f", red_ink="#b02523", yellow="#b58900", yellow_ink="#735700",
                green="#859900", green_ink="#566300", orange="#cb4b16", orange_ink="#9c3810",
                cyan="#2aa198", cyan_ink="#1b6f69", violet="#6c71c4", violet_ink="#50549e",
                blue="#268bd2", blue_ink="#1a6294", magenta="#d33682",
            ),
            "dark": dict(
                shell="#00212a", shell_raised="#00252f", shell_deep="#001b22", shell_text="#93a1a1",
                shell_muted="#839496", shell_strong="#fdf6e3",
                canvas="#002b36", surface="#073642", surface2="#0a3d4a", surface3="#0f4856",
                border="#164b58", border_strong="#22606f",
                heading="#eee8d5", text="#d3dada", muted="#a3b2b2", strong="#fdf6e3",
                accent="#268bd2", accent_ink="#6cb6ec", on_accent="#00212a",
                red="#dc322f", red_ink="#ff8a85", yellow="#b58900", yellow_ink="#e8bd3c",
                green="#859900", green_ink="#b5cc3a", orange="#cb4b16", orange_ink="#f59468",
                cyan="#2aa198", cyan_ink="#5fd1c6", violet="#6c71c4", violet_ink="#aeb1f0",
                blue="#268bd2", blue_ink="#6cb6ec", magenta="#e0609f",
            ),
        },
    ),
    "slate": (
        "Slate",
        "Neutral greys with one blue accent: colour is kept for severity, so alerts stand out.",
        {
            "light": dict(
                shell="#161b22", shell_raised="#1c2128", shell_deep="#0d1117", shell_text="#c9d1d9",
                shell_muted="#8b949e", shell_strong="#ffffff",
                canvas="#f3f5f8", surface="#ffffff", surface2="#eef1f5", surface3="#e2e7ee",
                border="#d8dee6", border_strong="#c2cad5",
                heading="#1b2230", text="#2b3441", muted="#566070", strong="#0f1622",
                accent="#2f6fde", accent_ink="#1f5bc4", on_accent="#ffffff",
                red="#d93636", red_ink="#b42323", yellow="#d29b00", yellow_ink="#7f5900",
                green="#2da44e", green_ink="#166f30", orange="#e16f24", orange_ink="#a64a17",
                cyan="#1b9aaa", cyan_ink="#0c6b78", violet="#8250df", violet_ink="#6639ba",
                blue="#2f6fde", blue_ink="#1f5bc4", magenta="#bf3989",
            ),
            "dark": dict(
                shell="#0a0d12", shell_raised="#10151c", shell_deep="#06080b", shell_text="#c9d1d9",
                shell_muted="#8b949e", shell_strong="#ffffff",
                canvas="#0d1117", surface="#161b22", surface2="#1c2330", surface3="#242c39",
                border="#2a3342", border_strong="#3a4556",
                heading="#e6edf3", text="#d0d7de", muted="#9ba5b0", strong="#f5f8fb",
                accent="#4c8dff", accent_ink="#79adff", on_accent="#0b1220",
                red="#f85149", red_ink="#ff8b84", yellow="#d29922", yellow_ink="#e3b341",
                green="#3fb950", green_ink="#56d364", orange="#db6d28", orange_ink="#f0883e",
                cyan="#2bb3be", cyan_ink="#39c5cf", violet="#a371f7", violet_ink="#bc9cf5",
                blue="#4c8dff", blue_ink="#79adff", magenta="#f778ba",
            ),
        },
    ),
    "arctic": (
        "Arctic",
        "Cool, desaturated blues (Nord): low arousal for long triage sessions.",
        {
            "light": dict(
                shell="#2e3440", shell_raised="#3b4252", shell_deep="#242933", shell_text="#d8dee9",
                shell_muted="#aeb7c7", shell_strong="#eceff4",
                canvas="#eceff4", surface="#f8f9fb", surface2="#e5e9f0", surface3="#d8dee9",
                border="#d3d9e3", border_strong="#bcc5d3",
                heading="#2e3440", text="#2f3542", muted="#4f596c", strong="#242933",
                accent="#5e81ac", accent_ink="#46638a", on_accent="#ffffff",
                red="#bf616a", red_ink="#9b3a44", yellow="#ebcb8b", yellow_ink="#6e5310",
                green="#a3be8c", green_ink="#456230", orange="#d08770", orange_ink="#8f4630",
                cyan="#88c0d0", cyan_ink="#2a6474", violet="#b48ead", violet_ink="#74506d",
                blue="#81a1c1", blue_ink="#46638a", magenta="#b48ead",
            ),
            "dark": dict(
                shell="#242933", shell_raised="#2a303c", shell_deep="#1f232b", shell_text="#d8dee9",
                shell_muted="#9aa4b8", shell_strong="#eceff4",
                canvas="#2e3440", surface="#353c4a", surface2="#3b4252", surface3="#434c5e",
                border="#4c566a", border_strong="#5d687e",
                heading="#eceff4", text="#eef1f5", muted="#c8cfdb", strong="#f4f6f9",
                accent="#88c0d0", accent_ink="#9fd0de", on_accent="#242933",
                red="#bf616a", red_ink="#f3b0b6", yellow="#ebcb8b", yellow_ink="#ebcb8b",
                green="#a3be8c", green_ink="#c3dbaf", orange="#d08770", orange_ink="#eebaa9",
                cyan="#88c0d0", cyan_ink="#a8d6e3", violet="#b48ead", violet_ink="#dcc2d7",
                blue="#81a1c1", blue_ink="#b5cbe1", magenta="#d6b7d0",
            ),
        },
    ),
    "forest": (
        "Forest",
        "Green-tinted neutrals: a restorative, low-fatigue palette for long shifts.",
        {
            "light": dict(
                shell="#17261d", shell_raised="#1e3126", shell_deep="#101a14", shell_text="#c7d6cc",
                shell_muted="#8fa596", shell_strong="#f1f7f2",
                canvas="#eef3ee", surface="#fbfdfb", surface2="#e4ece5", surface3="#d7e2d9",
                border="#d2ddd4", border_strong="#b9c9bd",
                heading="#1d3326", text="#24372b", muted="#4a5e52", strong="#132419",
                accent="#2d7a6a", accent_ink="#22675a", on_accent="#ffffff",
                red="#c8423b", red_ink="#a32f29", yellow="#c79a1e", yellow_ink="#735709",
                green="#3c8d4f", green_ink="#286a38", orange="#cf6a2c", orange_ink="#984818",
                cyan="#2b8c8c", cyan_ink="#1b6666", violet="#6d5fb0", violet_ink="#544893",
                blue="#3a72b0", blue_ink="#2b5a8f", magenta="#b2457f",
            ),
            "dark": dict(
                shell="#0b120e", shell_raised="#0e1712", shell_deep="#080d0a", shell_text="#c3d3c8",
                shell_muted="#84998b", shell_strong="#f3f8f4",
                canvas="#101814", surface="#17221c", surface2="#1d2a23", surface3="#24342b",
                border="#2a3b31", border_strong="#3a5043",
                heading="#e4efe7", text="#d0ded4", muted="#9db3a5", strong="#f3f8f4",
                accent="#4fb59c", accent_ink="#6cceb4", on_accent="#0b120e",
                red="#e5534b", red_ink="#f58d86", yellow="#d4a72c", yellow_ink="#e6c25e",
                green="#57ab5a", green_ink="#7dd58f", orange="#d9783a", orange_ink="#f0a66e",
                cyan="#39a8a8", cyan_ink="#6fd0d0", violet="#8f80d9", violet_ink="#b4a9ec",
                blue="#5b93d6", blue_ink="#8fbaee", magenta="#e57fb4",
            ),
        },
    ),
    "amber": (
        "Night shift",
        "Warm amber with little blue light: easier on the eyes on night shifts.",
        {
            "light": dict(
                shell="#2a1f14", shell_raised="#33261a", shell_deep="#1f170e", shell_text="#e3d2b6",
                shell_muted="#b29d7d", shell_strong="#fbf3e4",
                canvas="#f5efe4", surface="#fffaf1", surface2="#efe6d6", surface3="#e5d9c3",
                border="#e0d4bf", border_strong="#cdbd9f",
                heading="#3a2a17", text="#3d2e1b", muted="#62503a", strong="#2a1d0f",
                accent="#b0611a", accent_ink="#8c4b0e", on_accent="#fffaf1",
                red="#c0392b", red_ink="#9c2d21", yellow="#b8860b", yellow_ink="#6e5000",
                green="#6a8a24", green_ink="#4a6312", orange="#c8651b", orange_ink="#924710",
                cyan="#3d8c84", cyan_ink="#26655e", violet="#8a5aa8", violet_ink="#6a4285",
                blue="#4f7bb0", blue_ink="#365e8f", magenta="#b24a7a",
            ),
            "dark": dict(
                shell="#110d08", shell_raised="#14100a", shell_deep="#0c0906", shell_text="#e0caa4",
                shell_muted="#a8916d", shell_strong="#fbefd9",
                canvas="#17120c", surface="#201911", surface2="#281f15", surface3="#31261a",
                border="#3a2d1f", border_strong="#4d3c29",
                heading="#f3e2c4", text="#e8d4b0", muted="#bea783", strong="#fbefd9",
                accent="#e0953a", accent_ink="#f0a64a", on_accent="#17120c",
                red="#e0604c", red_ink="#f39280", yellow="#d9a93a", yellow_ink="#e8c060",
                green="#9aab4e", green_ink="#bdcb72", orange="#e08a3a", orange_ink="#f2aa62",
                cyan="#6fa892", cyan_ink="#98c9b3", violet="#b483ab", violet_ink="#d6aacd",
                blue="#8a9cbc", blue_ink="#b3c0d6", magenta="#e88ab0",
            ),
        },
    ),
    "contrast": (
        "High contrast",
        "Maximum contrast and strong borders, for bright rooms, projectors and low vision.",
        {
            "light": dict(
                shell="#000000", shell_raised="#000000", shell_deep="#000000", shell_text="#ffffff",
                shell_muted="#d0d0d0", shell_strong="#ffffff",
                canvas="#ffffff", surface="#ffffff", surface2="#f0f0f0", surface3="#e0e0e0",
                border="#767676", border_strong="#3d3d3d",
                heading="#000000", text="#111111", muted="#3d3d3d", strong="#000000",
                accent="#0047ab", accent_ink="#003a8c", on_accent="#ffffff",
                red="#b00000", red_ink="#a00000", yellow="#8a5a00", yellow_ink="#6b4500",
                green="#006b1f", green_ink="#005a1a", orange="#b34700", orange_ink="#8f3900",
                cyan="#006b75", cyan_ink="#005a62", violet="#5a2ca0", violet_ink="#4b2387",
                blue="#0047ab", blue_ink="#003a8c", magenta="#a0005f",
            ),
            "dark": dict(
                shell="#000000", shell_raised="#000000", shell_deep="#000000", shell_text="#ffffff",
                shell_muted="#d0d0d0", shell_strong="#ffffff",
                canvas="#000000", surface="#0a0a0a", surface2="#1a1a1a", surface3="#2a2a2a",
                border="#8a8a8a", border_strong="#c8c8c8",
                heading="#ffffff", text="#f2f2f2", muted="#c8c8c8", strong="#ffffff",
                accent="#4da3ff", accent_ink="#7dbbff", on_accent="#000000",
                red="#ff6b6b", red_ink="#ff8a8a", yellow="#ffd23f", yellow_ink="#ffd23f",
                green="#5be37a", green_ink="#5be37a", orange="#ff9f43", orange_ink="#ff9f43",
                cyan="#4fe0e6", cyan_ink="#4fe0e6", violet="#c3a6ff", violet_ink="#c3a6ff",
                blue="#7dbbff", blue_ink="#7dbbff", magenta="#ff7ac6",
            ),
        },
    ),
    "colorblind": (
        "Colour-blind safe",
        "Okabe-Ito status colours: danger, warning and success stay distinct with any colour-vision deficiency.",
        {
            "light": dict(
                shell="#1a1f27", shell_raised="#222833", shell_deep="#12161c", shell_text="#cfd6df",
                shell_muted="#8f99a6", shell_strong="#ffffff",
                canvas="#f2f4f7", surface="#ffffff", surface2="#eceff3", surface3="#dfe4ea",
                border="#d6dbe2", border_strong="#bfc7d1",
                heading="#1a2029", text="#272f3b", muted="#545e6c", strong="#10151c",
                accent="#0072b2", accent_ink="#005f94", on_accent="#ffffff",
                red="#d55e00", red_ink="#a34700", yellow="#e69f00", yellow_ink="#7a5400",
                green="#009e73", green_ink="#007354", orange="#e69f00", orange_ink="#8a5a00",
                cyan="#56b4e9", cyan_ink="#1b6a96", violet="#cc79a7", violet_ink="#934170",
                blue="#0072b2", blue_ink="#005f94", magenta="#cc79a7",
            ),
            "dark": dict(
                shell="#0b0e12", shell_raised="#10141a", shell_deep="#07090c", shell_text="#cfd6df",
                shell_muted="#8f99a6", shell_strong="#ffffff",
                canvas="#11151b", surface="#181d25", surface2="#1f2530", surface3="#28303c",
                border="#2e3644", border_strong="#3f4a5b",
                heading="#eef2f6", text="#d6dde5", muted="#a2adba", strong="#f8fafc",
                accent="#56b4e9", accent_ink="#7cc8f2", on_accent="#0b0e12",
                red="#d55e00", red_ink="#ff9a52", yellow="#f0e442", yellow_ink="#f0e442",
                green="#009e73", green_ink="#2fd3a4", orange="#e69f00", orange_ink="#f2b33d",
                cyan="#56b4e9", cyan_ink="#7cc8f2", violet="#cc79a7", violet_ink="#e39cc3",
                blue="#56b4e9", blue_ink="#7cc8f2", magenta="#e39cc3",
            ),
        },
    ),
}
DEFAULT = ("solarized", "light")
HUES = ("red", "yellow", "green", "orange", "cyan", "violet", "blue")


def rgb(hex_):
    h = hex_.lstrip("#")
    return tuple(int(h[i : i + 2], 16) for i in (0, 2, 4))


def triplet(hex_):
    return ", ".join(map(str, rgb(hex_)))


def mix(a, b, t):
    """Colour a at weight t over colour b."""
    return "#" + "".join(f"{round(x * t + y * (1 - t)):02x}" for x, y in zip(rgb(a), rgb(b)))


def luminance(hex_):
    def chan(c):
        c /= 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (chan(c) for c in rgb(hex_))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a, b):
    hi, lo = sorted((luminance(a), luminance(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)


def checks(p):
    """(label, foreground, background, minimum ratio) for one palette."""
    out = []
    for bg in ("canvas", "surface"):
        out += [
            (f"text/{bg}", p["text"], p[bg], 7),
            (f"heading/{bg}", p["heading"], p[bg], 7),
            (f"muted/{bg}", p["muted"], p[bg], 4.5),
        ]
    out.append(("muted/surface2", p["muted"], p["surface2"], 4.5))
    for hue in ("accent",) + HUES:
        ink = p[f"{hue}_ink"]
        out.append((f"{hue}-ink/surface", ink, p["surface"], 4.5))
        out.append((f"{hue}-ink/chip", ink, mix(p[hue], p["surface"], 0.16), 4.5))
    out += [
        ("button text", p["on_accent"], p["accent_ink"], 4.5),
        ("shell text", p["shell_text"], p["shell_raised"], 4.5),
        ("shell muted", p["shell_muted"], p["shell_raised"], 4.5),
        ("shell muted/deep", p["shell_muted"], p["shell_deep"], 4.5),
        ("shell strong", p["shell_strong"], p["shell_raised"], 7),
    ]
    return out


def tokens(p, mode):
    dark = mode == "dark"
    toward = "#ffffff" if dark else "#000000"
    t = {
        "shell": p["shell"],
        "shell-raised": p["shell_raised"],
        "shell-deep": p["shell_deep"],
        "shell-text": p["shell_text"],
        "shell-muted": p["shell_muted"],
        "shell-strong": p["shell_strong"],
        "shell-line-rgb": triplet(p["shell_text"]),
        "canvas": p["canvas"],
        "canvas-rgb": triplet(p["canvas"]),
        "surface": p["surface"],
        "surface-2": p["surface2"],
        "surface-3": p["surface3"],
        "border": p["border"],
        "border-strong": p["border_strong"],
        "heading": p["heading"],
        "text": p["text"],
        "text-rgb": triplet(p["text"]),
        "text-muted": p["muted"],
        "placeholder": p["muted"],
        "strong": p["strong"],
        "strong-rgb": triplet(p["strong"]),
        "accent": p["accent"],
        "accent-rgb": triplet(p["accent"]),
        "accent-ink": p["accent_ink"],
        "accent-ink-rgb": triplet(p["accent_ink"]),
        "accent-hover": mix(p["accent_ink"], toward, 0.82),
        "accent-active": mix(p["accent_ink"], toward, 0.7),
        "accent-disabled": mix(p["accent_ink"], p["surface"], 0.45),
        "on-accent": p["on_accent"],
        "danger-hover": mix(p["red_ink"], toward, 0.82),
        "success-hover": mix(p["green_ink"], toward, 0.82),
        "shadow-rgb": "0, 0, 0" if dark else triplet(p["shell_deep"]),
        "shadow-alpha": "0.35" if dark else "0.06",
        "magenta": p["magenta"],
    }
    for hue in HUES:
        t[hue] = p[hue]
        t[f"{hue}-ink"] = p[f"{hue}_ink"]
        t[f"{hue}-rgb"] = triplet(p[hue])
        t[f"{hue}-ink-rgb"] = triplet(p[f"{hue}_ink"])
    # Chart series: readable on the card in both modes (inks in dark mode, pure hues in light mode).
    series = ("accent", "red", "green", "violet", "orange", "cyan")
    for i, hue in enumerate(series, start=1):
        t[f"chart-{i}"] = p[f"{hue}_ink"] if dark else p[hue]
    return t


def block(selector, t, mode):
    lines = [f"{selector} {{", f"    color-scheme: {mode};"]
    lines += [f"    --chimera-{k}: {v};" for k, v in t.items()]
    return "\n".join(lines) + "\n}\n"


def main():
    failures = []
    css = [
        "/* Generated by tools/gen_themes.py: edit the palettes there, not this file.\n"
        '   <html data-chimera-scheme="..." data-bs-theme="light|dark"> picks one; without the attributes the\n'
        "   default applies (Solarized light), which is also what the offline HTML report uses. */\n"
    ]
    for name, (label, note, modes) in SCHEMES.items():
        for mode, palette in modes.items():
            for what, fg, bg, minimum in checks(palette):
                ratio = contrast(fg, bg)
                if ratio < minimum:
                    failures.append(f"{name}/{mode} {what}: {ratio:.2f} < {minimum} ({fg} on {bg})")
            selector = f':root[data-chimera-scheme="{name}"][data-bs-theme="{mode}"]'
            if (name, mode) == DEFAULT:
                selector = f":root,\n{selector}"
            css.append(f"/* {label}, {mode}: {note} */\n" + block(selector, tokens(palette, mode), mode))
    print("\n".join(failures) or f"all contrast checks pass ({len(SCHEMES) * 2} palettes)")
    if failures:
        return 1
    if "--check" not in sys.argv:
        OUT.write_text("\n".join(css))
        print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
