# Web UI colour schemes

The top bar's palette button opens **Appearance**: Light, Dark or System (follows the operating system), and
one of seven colour schemes. The choice is kept in the browser (`localStorage`, key `chimera-theme`).

| Scheme | Why it is there |
|---|---|
| Solarized | The CHIMERA default: warm, low-glare background |
| Slate | Neutral greys with one blue accent, so colour only appears where severity is |
| Arctic | Cool, desaturated blues (Nord): calm, low arousal for long triage sessions |
| Forest | Green-tinted neutrals: restful, low eye fatigue on long shifts |
| Night shift | Warm amber with little blue light, for night work |
| High contrast | Projectors, bright rooms and low vision |
| Colour-blind safe | Okabe-Ito status colours: danger, warning and success stay distinct with any colour-vision deficiency |

Status colours keep the same meaning in every scheme (red = failed or malicious, yellow = queued or suspicious,
green = finished or benign), so switching schemes never changes how a result reads.

## How it works

- `drakrun/web/frontend/tools/gen_themes.py` holds the 14 palettes and generates `src/themes.css` (CSS custom
  properties under `<html data-chimera-scheme="…" data-bs-theme="light|dark">`). It refuses to write the file if
  a palette misses its contrast targets: body text and headings 7:1 (WCAG AAA) on the page and on cards;
  secondary text, every coloured word (also on its own tinted badge), sidebar text and button text 4.5:1 (AA).
- `src/chimera-theme.css` only uses the semantic tokens (`--chimera-canvas`, `--chimera-text`,
  `--chimera-accent-ink`, …), so a new scheme is a new palette and nothing else. Charts and the react-select
  pickers use the same tokens.
- `test/unit/test_frontend_themes.py` checks the contrast targets, that `themes.css` is regenerated and that
  the picker lists the same schemes.
- Checked in the browser on 25 Oct 2026: every text element of the analysis page (all 7 tabs and 6 static
  sub-tabs), the analyses list, verification runs, sandbox evasion and upload, in all 14 scheme × mode
  combinations: no text under 4.5:1 (3:1 for large text).

To add or change a scheme: edit `SCHEMES` in `tools/gen_themes.py` and `SCHEMES` in `src/themes.js`, run
`python3 tools/gen_themes.py`, rebuild.

## Pagination

The analyses list and verification runs show 25 rows per page (10, 25, 50 or 100). The page is in the URL
(`?page=3&per=50`), so reload, the back button and shared links keep the place; changing a filter goes back to
page 1. The score trend chart on the verification runs page still shows every run.
