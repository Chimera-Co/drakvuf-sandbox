import chimeraLight from "./assets/chimera-light.png";
import chimeraDark from "./assets/chimera-dark.png";

/**
 * CHIMERA brand mark — the single integration point for the approved creature
 * artwork. Everything that shows the mark (AppHeader, ChimeraIntro, and the
 * offline report's header) renders it through this component.
 *
 * Asset choice: the approved package ships both SVG and PNG of the creature.
 * The SVGs (src/assets/chimera-*.svg) are kept as the vector masters, but they
 * are auto-traced bitmaps — ~1000-2300 fragmented sub-paths with stray specks
 * and empty paths — and render as a muddy, speckled mark at display sizes. The
 * PNGs are clean renders, so they are what we display. This is the "technical
 * reason" the brief allows for preferring PNG. Swapping in a hand-built clean
 * SVG later means changing only the two imports above.
 *
 * Two approved variants, no third:
 *   - variant="light"  white creature  -> for dark backgrounds
 *                                          (Solarized shell, intro overlay)
 *   - variant="dark"   dark creature   -> for light backgrounds
 *
 * `size` is the rendered box in px (the artwork sits on a square canvas).
 * `className` and the decorative-image semantics are preserved from the
 * previous placeholder so existing layout and accessibility behaviour are
 * unchanged.
 */

const VARIANTS = {
    light: chimeraLight,
    dark: chimeraDark,
};

export function ChimeraLogo({ size = 28, variant = "light", className = "" }) {
    return (
        <img
            className={`chimera-mark ${className}`.trim()}
            src={VARIANTS[variant] ?? chimeraLight}
            width={size}
            height={size}
            alt=""
            aria-hidden="true"
            draggable="false"
        />
    );
}
