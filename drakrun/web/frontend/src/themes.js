import { useEffect, useState } from "react";

// Same names as tools/gen_themes.py (which generates themes.css); `swatch` is shown in the picker.
export const SCHEMES = [
    {
        id: "solarized",
        label: "Solarized",
        note: "Warm, low-glare paper; the CHIMERA default",
        swatch: ["#002b36", "#fdf6e3", "#268bd2", "#dc322f"],
    },
    {
        id: "slate",
        label: "Slate",
        note: "Neutral greys: colour only where severity is",
        swatch: ["#161b22", "#ffffff", "#2f6fde", "#d93636"],
    },
    {
        id: "arctic",
        label: "Arctic",
        note: "Cool, calm blues for long triage sessions",
        swatch: ["#2e3440", "#eceff4", "#5e81ac", "#bf616a"],
    },
    {
        id: "forest",
        label: "Forest",
        note: "Restful greens, low eye fatigue",
        swatch: ["#17261d", "#fbfdfb", "#2d7a6a", "#c8423b"],
    },
    {
        id: "amber",
        label: "Night shift",
        note: "Warm amber, little blue light",
        swatch: ["#110d08", "#fffaf1", "#e0953a", "#e0604c"],
    },
    {
        id: "contrast",
        label: "High contrast",
        note: "Projectors, bright rooms, low vision",
        swatch: ["#000000", "#ffffff", "#0047ab", "#b00000"],
    },
    {
        id: "colorblind",
        label: "Colour-blind safe",
        note: "Okabe-Ito status colours",
        swatch: ["#1a1f27", "#ffffff", "#0072b2", "#d55e00"],
    },
];
export const MODES = ["light", "dark", "system"];
const KEY = "chimera-theme";
const EVENT = "chimera-theme-change";
const DEFAULT = { scheme: "solarized", mode: "system" };

export function loadTheme() {
    try {
        const saved = JSON.parse(localStorage.getItem(KEY) || "null");
        if (
            saved &&
            SCHEMES.some((s) => s.id === saved.scheme) &&
            MODES.includes(saved.mode)
        )
            return saved;
    } catch {
        // private window, blocked storage or a bad value: use the default
    }
    return DEFAULT;
}

const systemDark = () =>
    typeof window !== "undefined" &&
    Boolean(window.matchMedia?.("(prefers-color-scheme: dark)").matches);

export function resolvedMode(theme) {
    if (theme.mode !== "system") return theme.mode;
    return systemDark() ? "dark" : "light";
}

export function applyTheme(theme) {
    const root = document.documentElement;
    root.setAttribute("data-chimera-scheme", theme.scheme);
    root.setAttribute("data-bs-theme", resolvedMode(theme));
    const meta = document.querySelector('meta[name="theme-color"]');
    const shell = getComputedStyle(root)
        .getPropertyValue("--chimera-shell")
        .trim();
    if (meta && shell) meta.setAttribute("content", shell);
}

export function saveTheme(theme) {
    try {
        localStorage.setItem(KEY, JSON.stringify(theme));
    } catch {
        // not persisted; still applied for this page
    }
    applyTheme(theme);
    window.dispatchEvent(new CustomEvent(EVENT, { detail: theme }));
}

// Called once from main.jsx before the first render; follows the OS setting while mode is "system".
export function initTheme() {
    applyTheme(loadTheme());
    window
        .matchMedia?.("(prefers-color-scheme: dark)")
        ?.addEventListener?.("change", () => {
            const theme = loadTheme();
            if (theme.mode === "system") saveTheme(theme);
        });
}

export function useTheme() {
    const [theme, setTheme] = useState(loadTheme);
    useEffect(() => {
        const onChange = (e) => setTheme(e.detail);
        window.addEventListener(EVENT, onChange);
        return () => window.removeEventListener(EVENT, onChange);
    }, []);
    return [theme, saveTheme];
}

// react-select draws with inline styles; point them at the theme tokens. `extra` entries wrap the base ones.
export function selectStyles(extra = {}) {
    const base = {
        control: (s, { isFocused }) => ({
            ...s,
            backgroundColor: "var(--chimera-surface)",
            borderColor: isFocused
                ? "var(--chimera-accent)"
                : "var(--chimera-border-strong)",
            boxShadow: isFocused
                ? "0 0 0 3px rgba(var(--chimera-accent-rgb), 0.16)"
                : "none",
            "&:hover": { borderColor: "var(--chimera-accent)" },
        }),
        menu: (s) => ({
            ...s,
            backgroundColor: "var(--chimera-surface)",
            border: "1px solid var(--chimera-border)",
            zIndex: 20,
        }),
        option: (s, { isFocused, isSelected }) => ({
            ...s,
            backgroundColor: isSelected
                ? "var(--chimera-accent-ink)"
                : isFocused
                  ? "rgba(var(--chimera-accent-rgb), 0.12)"
                  : "transparent",
            color: isSelected
                ? "var(--chimera-on-accent)"
                : "var(--chimera-text)",
        }),
        singleValue: (s) => ({ ...s, color: "var(--chimera-strong)" }),
        input: (s) => ({ ...s, color: "var(--chimera-strong)" }),
        placeholder: (s) => ({ ...s, color: "var(--chimera-placeholder)" }),
        multiValue: (s) => ({
            ...s,
            backgroundColor: "rgba(var(--chimera-accent-rgb), 0.14)",
        }),
        multiValueLabel: (s) => ({ ...s, color: "var(--chimera-accent-ink)" }),
        multiValueRemove: (s) => ({
            ...s,
            color: "var(--chimera-accent-ink)",
            "&:hover": {
                backgroundColor: "rgba(var(--chimera-red-rgb), 0.16)",
                color: "var(--chimera-red-ink)",
            },
        }),
        indicatorSeparator: (s) => ({
            ...s,
            backgroundColor: "var(--chimera-border)",
        }),
        dropdownIndicator: (s) => ({
            ...s,
            color: "var(--chimera-text-muted)",
        }),
        clearIndicator: (s) => ({ ...s, color: "var(--chimera-text-muted)" }),
        noOptionsMessage: (s) => ({
            ...s,
            color: "var(--chimera-text-muted)",
        }),
    };
    for (const [key, fn] of Object.entries(extra)) {
        const inner = base[key];
        base[key] = inner ? (s, state) => fn(inner(s, state), state) : fn;
    }
    return base;
}
