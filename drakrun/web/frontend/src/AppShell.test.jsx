import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { AppHeader, useSidebar } from "./App.jsx";

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
    fireEvent.click(screen.getByRole("button", { name: "Keep sidebar open" }));
    expect(screen.getByLabelText("mode").textContent).toBe("open");
    expect(JSON.parse(localStorage.getItem("chimera-sidebar")).report).toBe(
        "open",
    );
    cleanup();
    at("/");
    expect(screen.getByLabelText("mode").textContent).toBe("open");
    fireEvent.click(
        screen.getByRole("button", { name: "Fold sidebar to icons" }),
    );
    expect(screen.getByLabelText("mode").textContent).toBe("rail");
});
