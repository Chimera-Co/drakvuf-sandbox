import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render } from "@testing-library/react";
import { act } from "react";

afterEach(() => {
    cleanup();
    vi.useRealTimers();
    vi.unstubAllGlobals();
});

async function splash(reduced = false) {
    vi.resetModules();
    vi.useFakeTimers();
    vi.stubGlobal("matchMedia", () => ({ matches: reduced }));
    const { ChimeraIntro } = await import("./ChimeraIntro.jsx");
    return { ChimeraIntro, ...render(<ChimeraIntro />) };
}

it("holds the logo for 1.9 seconds, fades, and stays consumed on remount", async () => {
    const { container, unmount, ChimeraIntro } = await splash();
    expect(container.querySelector("video")).toBeNull();
    act(() => vi.advanceTimersByTime(1899));
    expect(container.querySelector(".chimera-intro--splash")).not.toBeNull();
    act(() => vi.advanceTimersByTime(1));
    expect(container.querySelector(".chimera-intro--exiting")).not.toBeNull();
    act(() => vi.advanceTimersByTime(420));
    expect(container.innerHTML).toBe("");
    unmount();
    expect(render(<ChimeraIntro />).container.innerHTML).toBe("");
});

it.each(["Escape", "Enter", " ", "click"])("skips on %s", async (key) => {
    const { container } = await splash();
    if (key === "click") fireEvent.click(container.firstChild);
    else fireEvent.keyDown(window, { key });
    expect(container.querySelector(".chimera-intro--exiting")).not.toBeNull();
    act(() => vi.advanceTimersByTime(420));
    expect(container.innerHTML).toBe("");
});

it("uses a shorter static hold for reduced motion", async () => {
    const { container } = await splash(true);
    act(() => vi.advanceTimersByTime(1100));
    expect(container.querySelector(".chimera-intro--exiting")).not.toBeNull();
});
