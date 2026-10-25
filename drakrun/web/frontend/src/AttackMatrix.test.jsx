import { afterEach, describe, expect, it } from "vitest";
import {
    cleanup,
    fireEvent,
    render,
    screen,
    within,
} from "@testing-library/react";
import {
    AttackMatrix,
    entriesFromTtps,
    sampleScope,
    techniqueName,
} from "./AttackMatrix.jsx";

afterEach(cleanup);

const summary = {
    startup: { process: 10 },
    processes: {
        1: { parent_seqid: null },
        10: { parent_seqid: 1 },
        11: { parent_seqid: 10 },
        20: { parent_seqid: 1 },
    },
    ttps: [
        {
            name: "inject",
            "att&ck": ["Defense Evasion::Process Injection [T1055]"],
            process_seqids: [11],
        },
        {
            name: "query network",
            "att&ck": [
                "Discovery::System Network Configuration Discovery [T1016]",
            ],
            process_seqids: [20],
        },
    ],
};

describe("ATT&CK matrix", () => {
    it("separates the sample tree from other guest processes", () => {
        const scope = sampleScope(summary);
        expect([...scope].sort()).toEqual([10, 11]);
        const entries = entriesFromTtps(summary.ttps, scope);
        expect(entries.map((e) => [e.technique, e.source])).toEqual([
            ["T1055", "dynamic"],
            ["T1016", "system"],
        ]);
    });
    it("groups techniques by tactic, marks observed vs capability, and shows details", () => {
        render(
            <AttackMatrix
                entries={[
                    { technique: "T1055", name: "inject", source: "dynamic" },
                    {
                        technique: "T1027.002",
                        name: "packed with UPX",
                        source: "static",
                    },
                ]}
                systemEntries={[
                    {
                        technique: "T1016",
                        name: "query network",
                        source: "system",
                    },
                ]}
            />,
        );
        expect(screen.queryByRole("group", { name: "Discovery" })).toBeNull();
        const evasion = screen.getByRole("group", { name: "Defense Evasion" });
        const cells = within(evasion).getAllByRole("button");
        expect(cells[0].className).toContain("is-observed");
        expect(cells[1].className).toContain("is-potential");
        expect(within(cells[1]).getByText(/Software Packing/)).toBeTruthy();
        fireEvent.click(cells[0]);
        expect(
            screen
                .getByRole("link", { name: "ATT&CK page" })
                .getAttribute("href"),
        ).toBe("https://attack.mitre.org/techniques/T1055/");
        fireEvent.click(screen.getByRole("switch"));
        expect(screen.getByRole("group", { name: "Discovery" })).toBeTruthy();
    });
    it("names sub-techniques with their parent", () => {
        expect(techniqueName("T1027.002")).toBe(
            "Obfuscated Files or Information: Software Packing",
        );
        expect(techniqueName("T9999")).toBe("T9999");
    });
});
