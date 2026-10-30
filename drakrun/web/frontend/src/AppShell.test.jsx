import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
    cleanup,
    fireEvent,
    render,
    screen,
    within,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import App, { AppHeader, useSidebar } from "./App.jsx";

// the pages themselves are not under test (and pull in the VNC viewer)
vi.mock("./AnalysisList.jsx", () => ({ default: () => null }));
vi.mock("./UploadView.jsx", () => ({ default: () => null }));
vi.mock("./AnalysisView.jsx", () => ({ default: () => null }));
vi.mock("./SandboxEvasion.jsx", () => ({ default: () => null }));
vi.mock("./EvasionScanView.jsx", () => ({ default: () => null }));
vi.mock("./VerificationRuns.jsx", () => ({ default: () => null }));
vi.mock("./ChimeraIntro.jsx", () => ({ ChimeraIntro: () => null }));

function Shell() {
    const sidebar = useSidebar();
    return (
        <>
            <AppHeader sidebar={sidebar} />
            <output aria-label="mode">{sidebar.mode}</output>
            <output aria-label="peek">{String(sidebar.peek)}</output>
            <button onClick={() => sidebar.setMode("open")}>Pin open</button>
            <button onClick={() => sidebar.setMode("rail")}>
                Fold to icons
            </button>
        </>
    );
}
const at = (path) =>
    render(
        <MemoryRouter initialEntries={[path]}>
            <Shell />
        </MemoryRouter>,
    );

beforeEach(() => localStorage.clear());
afterEach(cleanup);

it("folds the sidebar on reports by default and remembers the choice per page kind", () => {
    at("/analysis/123");
    expect(screen.getByLabelText("mode").textContent).toBe("rail");
    fireEvent.click(screen.getByRole("button", { name: "Pin open" }));
    expect(screen.getByLabelText("mode").textContent).toBe("open");
    expect(JSON.parse(localStorage.getItem("chimera-sidebar")).report).toBe(
        "open",
    );
    cleanup();
    at("/");
    expect(screen.getByLabelText("mode").textContent).toBe("open");
    fireEvent.click(screen.getByRole("button", { name: "Fold to icons" }));
    expect(screen.getByLabelText("mode").textContent).toBe("rail");
});

it("the logo links to the Home page; Analyses stays the default page", () => {
    at("/");
    expect(screen.getByRole("link", { name: /CHIMERA/ })).toHaveAttribute(
        "href",
        "/home",
    );
});

it("opens Home from the logo and the docs from the sidebar", () => {
    vi.stubGlobal("__APP_VERSION__", "test");
    window.scrollTo = vi.fn(); // jsdom has no scrolling; the docs page scrolls on navigation
    render(
        <MemoryRouter initialEntries={["/"]}>
            <App />
        </MemoryRouter>,
    );
    expect(
        screen.queryByRole("heading", { name: "What CHIMERA is" }),
    ).toBeNull();
    fireEvent.click(screen.getByRole("link", { name: /CHIMERA/ }));
    expect(
        screen.getByRole("heading", { name: "What CHIMERA is" }),
    ).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("link", { name: "Home" })).toHaveClass(
        "active",
    );
    fireEvent.click(within(nav).getByRole("link", { name: "Documentation" }));
    expect(
        screen.getByRole("heading", {
            level: 1,
            name: "CHIMERA documentation",
        }),
    ).toBeInTheDocument();
    vi.unstubAllGlobals();
});

it("opens and closes the phone menu without changing the pinned preference", () => {
    at("/analysis/123");
    fireEvent.click(screen.getByRole("button", { name: "Open menu" }));
    expect(screen.getByLabelText("peek").textContent).toBe("true");
    fireEvent.click(screen.getByRole("button", { name: "Close menu" }));
    expect(screen.getByLabelText("peek").textContent).toBe("false");
    expect(screen.getByLabelText("mode").textContent).toBe("rail");
});
