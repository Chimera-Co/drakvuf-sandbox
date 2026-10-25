import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { ThemePicker } from "./ThemePicker.jsx";
import { initTheme, loadTheme, SCHEMES } from "./themes.js";

beforeEach(() => localStorage.clear());
afterEach(cleanup);

describe("theme picker", () => {
    it("applies the saved theme before render and falls back on bad data", () => {
        localStorage.setItem(
            "chimera-theme",
            JSON.stringify({ scheme: "forest", mode: "dark" }),
        );
        initTheme();
        expect(document.documentElement.dataset.chimeraScheme).toBe("forest");
        expect(document.documentElement.dataset.bsTheme).toBe("dark");
        localStorage.setItem("chimera-theme", "{not json");
        expect(loadTheme()).toEqual({ scheme: "solarized", mode: "system" });
    });
    it("switches scheme and mode and remembers them", () => {
        render(<ThemePicker />);
        fireEvent.click(screen.getByRole("button", { name: "Appearance" }));
        const dialog = screen.getByRole("dialog", { name: "Appearance" });
        expect(screen.getAllByRole("radio", { name: /./ }).length).toBe(
            SCHEMES.length + 3,
        );
        fireEvent.click(screen.getByLabelText("Dark"));
        fireEvent.click(screen.getByLabelText(/Night shift/));
        expect(document.documentElement.dataset.bsTheme).toBe("dark");
        expect(document.documentElement.dataset.chimeraScheme).toBe("amber");
        expect(JSON.parse(localStorage.getItem("chimera-theme"))).toEqual({
            scheme: "amber",
            mode: "dark",
        });
        fireEvent.keyDown(document, { key: "Escape" });
        expect(dialog.isConnected).toBe(false);
    });
});
