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

Every long table pages: the analyses list and verification runs (page in the URL, `?page=3&per=50`, so reload,
the back button and shared links keep the place), and the report tables, structured logs, static tables and
memory dumps (page kept in the component). The bar shows "Page X of Y · a–b of n", a page-number box once there
are more than 7 pages, and 10, 25, 50, 100 or All rows per page (All stops at 5000 rows). Changing a filter goes
back to page 1. The score trend chart on the verification runs page still shows every run.

## Layout

- The top bar stays put. The menu button (three lines) folds the sidebar to an icon rail or pins it open; on an
  analysis report it starts folded so the report gets the width. Hovering or focusing the rail opens it over
  the page without moving the content; Escape or a click outside closes it. The choice is remembered per page
  type (`chimera-sidebar` in localStorage). On phones the sidebar is hidden and the menu button opens it.
- An analysis report opens in the Simple view (key facts, what the sample did, ATT&CK matrix, indicators,
  limits of the run); Advanced has every table, log, the static analysis and the memory dumps. The choice is
  remembered (`chimera-report-view`).
- Once the process tree scrolls out of view a "Process tree" tab on the left edge opens it as a drawer; an
  "Outline" tab on the right lists the report's sections with the current one marked.
- Tables size each column to its content: short values stay on one line, long ones wrap, process columns wrap
  their chips (12 at most, then a count). A table wider than the page scrolls sideways inside its frame with
  the header row fixed.
