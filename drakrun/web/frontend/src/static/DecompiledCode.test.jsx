import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { DecompiledCodeTab } from "./DecompiledCode.jsx";
import {
    getDeepStatic,
    getMobsf,
    getMobsfSource,
    getStaticReport,
} from "../api.js";
import pe from "../__fixtures__/static-pe.json";
import ghidra from "../__fixtures__/deep-ghidra.json";
vi.mock("../api.js");
afterEach(() => {
    cleanup();
    vi.resetAllMocks();
});
describe("decompiled code tab", () => {
    it("shows Ghidra's functions with highlighted C", async () => {
        getStaticReport.mockResolvedValue(pe);
        getDeepStatic.mockResolvedValue(ghidra);
        const { container } = render(<DecompiledCodeTab analysisId="a1" />);
        expect(await screen.findByText(/Ghidra 11/)).toBeInTheDocument();
        expect(container.querySelector(".syntax-keyword")).not.toBeNull();
        // decompiler output is shown as text, never as markup
        expect(container.querySelector("script")).toBeNull();
    });
    it("explains when the file is not PE or ELF", async () => {
        getStaticReport.mockResolvedValue({ type: { format: "pdf" } });
        render(<DecompiledCodeTab analysisId="a1" />);
        expect(
            await screen.findByText(/available only for PE and ELF/),
        ).toBeInTheDocument();
    });
    it("browses an APK's decompiled Java with the app's own code first", async () => {
        getStaticReport.mockResolvedValue({ type: { format: "apk" } });
        getMobsf.mockResolvedValue({
            schema: "chimera-mobsf/1",
            sources: {
                package: "com.example.light",
                found: 2,
                files: [
                    {
                        path: "com/example/light/Main.java",
                        size: 40,
                        app: true,
                    },
                    { path: "okhttp3/Call.kt", size: 20, app: false },
                ],
            },
        });
        getMobsfSource.mockImplementation(({ path }) =>
            Promise.resolve(
                path.endsWith(".kt")
                    ? "fun call() {}"
                    : "@Override\npublic class Main { int x = 1; }",
            ),
        );
        const { container } = render(<DecompiledCodeTab analysisId="a1" />);
        expect(
            await screen.findByLabelText(
                "Decompiled com/example/light/Main.java",
            ),
        ).toBeInTheDocument();
        expect(screen.queryByText("Call.kt")).toBeNull();
        expect(container.querySelector(".syntax-keyword").textContent).toBe(
            "public",
        );
        fireEvent.click(screen.getByRole("treeitem", { name: "Main.java" }));
        expect(
            screen.getByRole("treeitem", { name: "Main.java" }),
        ).toHaveAttribute("aria-selected", "true");
        fireEvent.click(screen.getByRole("button", { name: "Collapse all" }));
        expect(
            screen.queryByRole("treeitem", { name: "Main.java" }),
        ).toBeNull();
        fireEvent.click(screen.getByRole("button", { name: "light" }));
        expect(
            screen.getByRole("treeitem", { name: "Main.java" }),
        ).toBeVisible();
        fireEvent.click(screen.getByRole("treeitem", { name: "okhttp3" }));
        fireEvent.click(screen.getByRole("treeitem", { name: "Call.kt" }));
        expect(
            await screen.findByLabelText("Decompiled okhttp3/Call.kt"),
        ).toBeInTheDocument();
        expect(screen.getByText("Kotlin")).toBeInTheDocument();
        expect(screen.getAllByRole("tab")).toHaveLength(2);
        fireEvent.click(screen.getByRole("tab", { name: "Main.java" }));
        expect(
            await screen.findByLabelText(
                "Decompiled com/example/light/Main.java",
            ),
        ).toBeInTheDocument();
        fireEvent.click(
            screen.getByRole("button", {
                name: "Close com/example/light/Main.java",
            }),
        );
        expect(screen.getByRole("tab", { name: "Call.kt" })).toHaveAttribute(
            "aria-selected",
            "true",
        );
    });
});
