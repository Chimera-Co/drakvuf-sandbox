import { useEffect, useRef, useState } from "react";
import { ChimeraLogo } from "./ChimeraLogo.jsx";

/**
 * Themed logo splash, shown once per page load before fading into the app.
 * Click, Escape, Enter or Space skips it. Reduced motion uses a shorter static
 * hold. The app loads underneath; routes and client-side navigation are unchanged.
 * Styling / keyframes live in chimera-theme.css section 15.
 */

// Module scope: survives re-renders and route changes within one page load,
// resets on a real document reload. This is the whole "once per page load"
// mechanism.
let introConsumedThisPageLoad = false;

/** Static logo splash duration. */
const SPLASH_MS = 1900;
/** Fade duration when leaving the overlay; keep in step with the CSS. */
const EXIT_MS = 420;
/** Reduced-motion path: a brief static hold. */
const REDUCED_MOTION_MS = 1100;

function prefersReducedMotion() {
    return (
        typeof window !== "undefined" &&
        window.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true
    );
}

export function ChimeraIntro() {
    // splash -> exiting -> done
    const [phase, setPhase] = useState(() =>
        introConsumedThisPageLoad ? "done" : "splash",
    );
    const reducedMotion = useRef(prefersReducedMotion()).current;

    // Consume the intro as soon as we commit to showing it, so any remount
    // inside the same page load does not replay it.
    useEffect(() => {
        if (phase !== "done") introConsumedThisPageLoad = true;
    }, [phase]);

    // Lock page scroll while the overlay is up.
    useEffect(() => {
        if (phase === "done") return;
        const root = document.documentElement;
        const body = document.body;
        const prevRoot = root.style.overflow;
        const prevBody = body.style.overflow;
        root.style.overflow = "hidden";
        body.style.overflow = "hidden";
        return () => {
            root.style.overflow = prevRoot;
            body.style.overflow = prevBody;
        };
    }, [phase]);

    // Keyboard: Escape / Enter / Space skip the whole intro. Window-level, so
    // focus is never trapped.
    useEffect(() => {
        if (phase === "done" || phase === "exiting") return;
        const onKey = (e) => {
            if (e.key === "Escape" || e.key === "Enter" || e.key === " ") {
                setPhase("exiting");
            }
        };
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [phase]);

    // Splash timer -> next phase.
    useEffect(() => {
        if (phase !== "splash") return;
        const t = setTimeout(
            () => setPhase("exiting"),
            reducedMotion ? REDUCED_MOTION_MS : SPLASH_MS,
        );
        return () => clearTimeout(t);
    }, [phase, reducedMotion]);

    // Exit fade -> unmount.
    useEffect(() => {
        if (phase !== "exiting") return;
        const t = setTimeout(() => setPhase("done"), EXIT_MS);
        return () => clearTimeout(t);
    }, [phase]);

    if (phase === "done") return null;

    const leave = () => setPhase("exiting");

    return (
        <div
            className={`chimera-intro chimera-intro--${phase}`}
            role="presentation"
            aria-hidden="true"
            onClick={leave}
        >
            <div className="chimera-intro__splash">
                <div className="chimera-intro__mark">
                    {/* Every scheme's shell is dark -> white ("light") creature. */}
                    <ChimeraLogo size={168} variant="light" />
                </div>
                <div className="chimera-intro__wordmark">Chimera</div>
                <div className="chimera-intro__rule" />
            </div>
        </div>
    );
}
