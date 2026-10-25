import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import MemoryDumps from "./MemoryDumps.jsx";
import { getMemdumps } from "./api.js";
vi.mock("./api.js");
afterEach(() => {
    cleanup();
    vi.resetAllMocks();
});
const doc = {
    schema: "chimera-memdumps/1",
    dumps_total: 5,
    duplicates: 1,
    skipped: 2,
    wall_s: 12.5,
    scanned: [
        {
            member: "dumps/a.mm",
            size: 2 << 20,
            pid: 42,
            process: "sample.exe",
            reason: "Remote thread",
            address: "0x400000",
            sample_tree: true,
            sha256: "ab".repeat(32),
            format: "pe",
            pe_kind: "exe",
            level: "high",
            score: 80,
            yara: ["CobaltStrike_Beacon"],
            findings: [{ id: "f1", title: "Embedded PE", severity: "high" }],
            embedded_executables: 1,
            iocs: { domains: ["evil.test"] },
        },
        {
            member: "dumps/b.mm",
            size: 4096,
            pid: 7,
            process: "explorer.exe",
            reason: "Stack heuristic",
            sha256: "cd".repeat(32),
            format: "pe",
            level: "clean",
            score: 0,
            yara: [],
            findings: [],
        },
    ],
};
describe("memory dumps", () => {
    it("summarises the scan and lists dumps with YARA hits", async () => {
        getMemdumps.mockResolvedValue(doc);
        render(<MemoryDumps analysisId="x" />);
        const table = await screen.findByRole("table", {
            name: "Scanned memory dumps",
        });
        expect(
            screen.getByText("With YARA matches").nextSibling.textContent,
        ).toBe("1");
        const rows = within(table).getAllByRole("row");
        expect(rows).toHaveLength(3);
        expect(within(rows[1]).getByText("CobaltStrike_Beacon")).toBeTruthy();
        expect(within(rows[1]).getByText("sample")).toBeTruthy();
        expect(within(rows[1]).getByText("evil.test")).toBeTruthy();
        expect(within(rows[2]).getByText("4 KiB")).toBeTruthy();
    });
    it("explains a missing scan", async () => {
        getMemdumps.mockRejectedValue({ response: { status: 404 } });
        render(<MemoryDumps analysisId="x" />);
        expect(await screen.findByText(/not scanned yet/)).toBeTruthy();
    });
});
