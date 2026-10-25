import { useEffect, useRef, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
    faCircleHalfStroke,
    faDesktop,
    faMoon,
    faPalette,
    faSun,
} from "@fortawesome/free-solid-svg-icons";
import { MODES, SCHEMES, useTheme } from "./themes.js";

const MODE_ICON = { light: faSun, dark: faMoon, system: faDesktop };

export function ThemePicker() {
    const [theme, setTheme] = useTheme();
    const [open, setOpen] = useState(false);
    const box = useRef(null);
    useEffect(() => {
        if (!open) return undefined;
        const onDown = (e) => {
            if (box.current && !box.current.contains(e.target)) setOpen(false);
        };
        const onKey = (e) => e.key === "Escape" && setOpen(false);
        document.addEventListener("mousedown", onDown);
        document.addEventListener("keydown", onKey);
        return () => {
            document.removeEventListener("mousedown", onDown);
            document.removeEventListener("keydown", onKey);
        };
    }, [open]);
    return (
        <div className="chimera-theme-picker ms-auto me-3" ref={box}>
            <button
                type="button"
                className="chimera-theme-toggle"
                aria-expanded={open}
                aria-controls="chimera-theme-panel"
                aria-label="Appearance"
                title="Appearance: colour scheme and light or dark mode"
                onClick={() => setOpen((v) => !v)}
            >
                <FontAwesomeIcon icon={faPalette} />
                <FontAwesomeIcon
                    icon={
                        theme.mode === "system"
                            ? faCircleHalfStroke
                            : MODE_ICON[theme.mode]
                    }
                    className="ms-2"
                />
            </button>
            {open ? (
                <div
                    id="chimera-theme-panel"
                    className="chimera-theme-panel"
                    role="dialog"
                    aria-label="Appearance"
                >
                    <fieldset>
                        <legend>Mode</legend>
                        <div className="chimera-theme-modes">
                            {MODES.map((mode) => (
                                <label
                                    key={mode}
                                    className={
                                        theme.mode === mode ? "active" : ""
                                    }
                                >
                                    <input
                                        type="radio"
                                        name="chimera-mode"
                                        value={mode}
                                        checked={theme.mode === mode}
                                        onChange={() =>
                                            setTheme({ ...theme, mode })
                                        }
                                    />
                                    <FontAwesomeIcon icon={MODE_ICON[mode]} />
                                    <span>
                                        {mode[0].toUpperCase() + mode.slice(1)}
                                    </span>
                                </label>
                            ))}
                        </div>
                    </fieldset>
                    <fieldset>
                        <legend>Colour scheme</legend>
                        {SCHEMES.map((s) => (
                            <label
                                key={s.id}
                                className={`chimera-theme-scheme ${theme.scheme === s.id ? "active" : ""}`}
                            >
                                <input
                                    type="radio"
                                    name="chimera-scheme"
                                    value={s.id}
                                    checked={theme.scheme === s.id}
                                    onChange={() =>
                                        setTheme({ ...theme, scheme: s.id })
                                    }
                                />
                                <span
                                    className="chimera-theme-swatch"
                                    aria-hidden="true"
                                >
                                    {s.swatch.map((c) => (
                                        <span
                                            key={c}
                                            style={{ backgroundColor: c }}
                                        />
                                    ))}
                                </span>
                                <span>
                                    <span className="d-block fw-semibold">
                                        {s.label}
                                    </span>
                                    <span className="d-block small text-muted">
                                        {s.note}
                                    </span>
                                </span>
                            </label>
                        ))}
                    </fieldset>
                    <div className="small text-muted px-1">
                        Every scheme has a light and a dark version and meets
                        WCAG AA contrast (AAA for body text). Saved in this
                        browser only.
                    </div>
                </div>
            ) : null}
        </div>
    );
}
