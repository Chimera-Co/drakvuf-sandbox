import { useEffect, useRef, useState } from "react";
import { ChimeraLogo } from "./ChimeraLogo.jsx";

/**
 * CHIMERA landing / intro experience.
 *
 *   browser load  ->  static logo splash  ->  full-bleed landing video  ->  app
 *
 * Plays ONCE PER PAGE LOAD:
 *   - a full browser reload (F5 / Ctrl+R / fresh navigation) replays it, because
 *     the module below is re-evaluated and `introConsumedThisPageLoad` resets;
 *   - React re-renders and client-side React Router navigations do NOT replay
 *     it, because <ChimeraIntro> is mounted once by App.jsx (outside <Routes>)
 *     and the module flag stays set for the life of the document.
 *
 * No sessionStorage / localStorage / cookie — the brief requires the sequence
 * on every reload.
 *
 * The overlay is a fixed, fully opaque layer covering the whole viewport. It
 * never calls the router, so whatever route the user loaded (e.g. /upload) is
 * exactly what they see when it finishes. It never blocks data loading — the
 * app mounts and fetches underneath it.
 *
 * Audio: the landing video plays UNMUTED and is never muted. Playback is
 * attempted automatically. If the browser's autoplay policy rejects audible
 * playback, that rejection is swallowed — it is NOT a completion signal and it
 * must NOT skip the video. The sequence advances only when the video fires
 * `ended` (normal) or `error` (a genuine media failure). There is no prompt,
 * no button, no click-to-enable-audio UI of any kind.
 *
 * Rendered only by App.jsx, never by the offline report entry point, so the
 * video is never pulled into the single-file report.
 *
 * Styling / keyframes live in chimera-theme.css section 15.
 */

// Module scope: survives re-renders and route changes within one page load,
// resets on a real document reload. This is the whole "once per page load"
// mechanism.
let introConsumedThisPageLoad = false;

const VIDEO_SRC = `${import.meta.env.BASE_URL}media/landing-page-animation.mp4`;

/** Static logo splash, shown before the video. */
const SPLASH_MS = 1900;
/** Fade duration when leaving the overlay; keep in step with the CSS. */
const EXIT_MS = 420;
/**
 * Last-resort guard for the video phase. Cleared as soon as the video fires
 * `ended`, so a normally-playing ~10s clip always finishes on its own event
 * and is never cut short by this. It only bites when `ended` never arrives at
 * all (autoplay blocked so the clip sits paused, or a truly stalled decode).
 */
const VIDEO_HARD_CAP_MS = 16000;
/** Reduced-motion path: a brief static hold, no breathing, no video. */
const REDUCED_MOTION_MS = 1100;

function prefersReducedMotion() {
    return (
        typeof window !== "undefined" &&
        window.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true
    );
}

export function ChimeraIntro() {
    // splash -> video -> exiting -> done   (reduced motion: splash -> exiting -> done)
    const [phase, setPhase] = useState(() =>
        introConsumedThisPageLoad ? "done" : "splash",
    );
    const videoRef = useRef(null);
    const reducedMotion = useRef(prefersReducedMotion()).current;

    // Consume the intro as soon as we commit to showing it, so any remount
    // inside the same page load does not replay it.
    useEffect(() => {
        if (phase !== "done") introConsumedThisPageLoad = true;
    }, [phase]);

    // Lock page scroll while the overlay is up: removes the scrollbar gutter so
    // the video is truly edge-to-edge, and stops the app scrolling behind it.
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
            () => setPhase(reducedMotion ? "exiting" : "video"),
            reducedMotion ? REDUCED_MOTION_MS : SPLASH_MS,
        );
        return () => clearTimeout(t);
    }, [phase, reducedMotion]);

    // Video phase.
    useEffect(() => {
        if (phase !== "video") return;
        // Last-resort guard only — see VIDEO_HARD_CAP_MS. `onEnded` clears it.
        const cap = setTimeout(() => setPhase("exiting"), VIDEO_HARD_CAP_MS);

        const el = videoRef.current;
        if (el) {
            try {
                el.currentTime = 0;
            } catch {
                /* not seekable yet — harmless, it is a fresh element at 0 */
            }
            el.muted = false;
            el.volume = 1;
            const p = el.play();
            if (p && typeof p.catch === "function") {
                // The browser's autoplay policy can reject audible playback.
                // This is NOT the video finishing — swallow it and stay in the
                // video phase. Do not mute, do not prompt, do not change phase.
                // The sequence still advances on `ended` / `error` / the cap.
                p.catch(() => {});
            }
        }

        return () => clearTimeout(cap);
    }, [phase]);

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
                    {/* Dark Solarized backdrop -> white ("light") creature. */}
                    <ChimeraLogo size={168} variant="light" />
                </div>
                <div className="chimera-intro__wordmark">Chimera</div>
                <div className="chimera-intro__rule" />
            </div>

            {/*
              Mounted only for the video phase so it always starts from frame
              one, after the splash. Not muted — the clip was authored with
              sound. `ended` is what advances the sequence; `error` only fires
              for a genuine media failure (a rejected play() Promise does not
              trigger it).
            */}
            {!reducedMotion && phase === "video" && (
                <video
                    ref={videoRef}
                    className="chimera-intro__video"
                    src={VIDEO_SRC}
                    autoPlay
                    playsInline
                    preload="auto"
                    onEnded={leave}
                    onError={leave}
                />
            )}
        </div>
    );
}
