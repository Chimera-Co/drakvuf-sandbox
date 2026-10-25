import { afterEach, describe, expect, it, vi } from "vitest";
import {
    cleanup,
    fireEvent,
    render,
    screen,
    within,
} from "@testing-library/react";
import {
    AttackMatrix,
    Capabilities,
    Code,
    FormatDetails,
    HighlightedCode,
    Strings,
    Structure,
} from "./StaticWorkspace.jsx";
import { StaticAnalysisTab } from "../AnalysisVerdict.jsx";
import { getDeepStatic, getStaticReport } from "../api.js";
import pe from "../__fixtures__/static-pe.json";
import deep from "../__fixtures__/deep-pe.json";
import ghidra from "../__fixtures__/deep-ghidra.json";
import formats from "../__fixtures__/static-formats.json";
vi.mock("../api.js");
vi.mock("recharts", () => ({
    ResponsiveContainer: ({ children }) => <div>{children}</div>,
    AreaChart: ({ children }) => <div>{children}</div>,
    Area: () => null,
    XAxis: () => null,
    YAxis: () => null,
    Tooltip: () => null,
    CartesianGrid: () => null,
    ReferenceLine: () => null,
}));
afterEach(() => {
    cleanup();
    vi.resetAllMocks();
});
describe("static workspace", () => {
    it("shows overview and switches sections with buttons", async () => {
        getStaticReport.mockResolvedValue(pe);
        getDeepStatic.mockResolvedValue(deep);
        render(<StaticAnalysisTab analysisId="test" />);
        expect(
            await screen.findByRole("region", { name: "Hashes" }),
        ).toBeTruthy();
        expect(screen.getByText("Assessment")).toBeTruthy();
        fireEvent.click(screen.getByRole("button", { name: "Structure" }));
        expect(screen.getByRole("table", { name: "Sections" })).toBeTruthy();
    });
    it("renders PE structure and entry marker", () => {
        render(<Structure data={pe} />);
        expect(screen.getByText("Entry")).toBeTruthy();
        expect(screen.getByText(/kernel32.dll/i)).toBeTruthy();
        expect(screen.getByLabelText("Entropy over file chart")).toBeTruthy();
    });
    it("filters strings and IOCs without interpreting markup", () => {
        render(
            <Strings
                data={{
                    universal: {
                        strings: {
                            ascii: 3,
                            sample: [
                                "ordinary",
                                "https://example.invalid",
                                "<script>bad</script>",
                            ],
                        },
                        iocs: { urls: ["https://example.invalid"] },
                    },
                }}
                deep={deep}
            />,
        );
        fireEvent.change(screen.getByLabelText("Search strings"), {
            target: { value: "ordinary" },
        });
        expect(screen.getByText("ordinary")).toBeTruthy();
        expect(screen.queryByText("https://example.invalid")).toBeNull();
        fireEvent.change(screen.getByLabelText("Search strings"), {
            target: { value: "" },
        });
        fireEvent.click(screen.getByLabelText("IOCs only"));
        expect(screen.getByText("https://example.invalid").tagName).toBe(
            "MARK",
        );
        expect(screen.queryByText("ordinary")).toBeNull();
    });
    it("groups capabilities and retains old attack and MBC IDs", () => {
        render(
            <Capabilities
                data={{
                    universal: {
                        yara: [
                            {
                                rule: "TestRule",
                                meta: {
                                    severity: "high",
                                    description: "Test detection",
                                },
                            },
                        ],
                    },
                }}
                deep={{
                    capa: {
                        rules: [
                            {
                                name: "launch",
                                namespace: "host/process",
                                attack: ["T1059"],
                                mbc: ["E1059"],
                            },
                        ],
                    },
                }}
            />,
        );
        expect(screen.getByText("host (1)")).toBeTruthy();
        expect(screen.getByText("T1059")).toBeTruthy();
        expect(screen.getByText("E1059")).toBeTruthy();
        expect(screen.getByText("Test detection")).toBeTruthy();
    });
    it("orders tactics and groups techniques with rule titles", () => {
        const rules = [
            {
                name: "launch",
                attack: [
                    {
                        id: "T1059",
                        tactic: "Execution",
                        technique: "Command interpreter",
                    },
                ],
            },
            {
                name: "other",
                attack: [
                    { id: "T1059", tactic: "Execution" },
                    { id: "T1003", tactic: "Credential Access" },
                ],
            },
        ];
        render(<AttackMatrix rules={rules} />);
        const matrix = screen.getByRole("region", { name: "ATT&CK matrix" });
        expect(within(matrix).getAllByText(/T1059/)).toHaveLength(1);
        expect(screen.getByTitle("launch other")).toBeTruthy();
        expect(matrix.textContent.indexOf("Execution")).toBeLessThan(
            matrix.textContent.indexOf("Credential Access"),
        );
    });
    it("selects, searches and copies decompiled functions", async () => {
        const writeText = vi.fn().mockResolvedValue();
        Object.defineProperty(navigator, "clipboard", {
            configurable: true,
            value: { writeText },
        });
        render(<Code deep={ghidra} format="pe" />);
        expect(screen.getByText(/Truncated:/)).toBeTruthy();
        fireEvent.click(screen.getByRole("button", { name: "Copy code" }));
        expect(await screen.findByText("Copied code")).toBeTruthy();
        expect(writeText).toHaveBeenCalledWith(ghidra.ghidra.functions[0].c);
        fireEvent.change(screen.getByLabelText("Search functions"), {
            target: { value: "worker" },
        });
        expect(screen.getByText("Decompilation error: timeout")).toBeTruthy();
    });
    it("highlights source and renders script tags as text", () => {
        const { container } = render(
            <HighlightedCode
                code={
                    "int main() { /* <script>alert(1)</script> */ return 42; }"
                }
            />,
        );
        expect(container.querySelector("script")).toBeNull();
        expect(container.textContent).toContain("<script>alert(1)</script>");
        expect(container.querySelector(".syntax-keyword").textContent).toBe(
            "return",
        );
    });
    it.each(Object.entries(formats))(
        "renders %s format details",
        (name, data) => {
            render(<FormatDetails data={data} />);
            expect(
                screen.getByRole("region", { name: "Format details" }),
            ).toBeTruthy();
            expect(
                screen.getByText(
                    name === "office"
                        ? "AutoOpen"
                        : name === "zip"
                          ? "invoice.exe"
                          : "android.permission.CAMERA · dangerous",
                ),
            ).toBeTruthy();
        },
    );
    it("renders PDF keywords and ELF available symbols", () => {
        const { rerender } = render(
            <FormatDetails
                data={{
                    type: { format: "pdf" },
                    pdf: { keywords: { "/JS": 2 } },
                }}
            />,
        );
        expect(screen.getByText("/JS")).toBeTruthy();
        rerender(
            <Structure
                data={{
                    elf: {
                        sections: [
                            {
                                name: ".text",
                                size: 20,
                                entropy: 7.5,
                                type: "SHT_PROGBITS",
                            },
                        ],
                        symbol_categories: { execution: ["execve"] },
                    },
                }}
            />,
        );
        expect(screen.getByText("Packed / encrypted")).toBeTruthy();
        expect(screen.getByText('["execve"]')).toBeTruthy();
    });
    it("explains missing decompiler and old structure data", () => {
        const { rerender } = render(<Code format="pdf" />);
        expect(screen.getByText(/only for PE and ELF/)).toBeTruthy();
        rerender(<Code format="pe" />);
        expect(screen.getByText(/Deep pass not run yet/)).toBeTruthy();
        rerender(<Code format="elf" deep={{}} />);
        expect(screen.getByText(/Decompiler is off/)).toBeTruthy();
    });
});
