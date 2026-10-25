import { afterEach, describe, expect, it } from "vitest";
import {
    cleanup,
    fireEvent,
    render,
    screen,
    within,
} from "@testing-library/react";
import { FileLayout, ImportsView, Indicators } from "./Insight.jsx";

afterEach(cleanup);

const pe = {
    type: { format: "pe" },
    file: { size: 4096 },
    indicators: [
        {
            id: "a",
            severity: 1,
            category: "header",
            title: "ASLR is not enabled",
            detail: "",
            evidence: "",
            attack: [],
        },
        {
            id: "b",
            severity: 3,
            category: "imports",
            title: "Import: CreateRemoteThread",
            detail: "Starts a thread in another process.",
            evidence: "kernel32.dll!CreateRemoteThread",
            attack: ["T1055"],
        },
        {
            id: "c",
            severity: 2,
            category: "strings",
            title: "String: shell command (1)",
            detail: "",
            evidence: "vssadmin delete shadows",
            attack: [],
        },
    ],
    indicators_summary: { high: 1, medium: 1, low: 1 },
    pe: {
        imports_annotated: [
            {
                dll: "kernel32.dll",
                description: "Core Win32 services.",
                severity: 0,
                functions: [
                    {
                        name: "CloseHandle",
                        severity: 0,
                        category: "misc",
                        description: "Closes a handle.",
                        attacker_use: "",
                        attack: [],
                    },
                    {
                        name: "CreateRemoteThread",
                        severity: 3,
                        category: "injection",
                        description: "Starts a thread in another process.",
                        attacker_use: "Code injection.",
                        attack: ["T1055"],
                    },
                ],
            },
            {
                dll: "user32.dll",
                description: "Windows UI.",
                severity: 0,
                functions: [
                    {
                        name: "GetAsyncKeyState",
                        severity: 2,
                        category: "keylogging_input",
                        description: "Reads a key state.",
                        attacker_use: "Keylogging.",
                        attack: ["T1056.001"],
                    },
                ],
            },
        ],
        imports_summary: {
            categories: { misc: 1, injection: 1, keylogging_input: 1 },
            total_count: 3,
            flagged_count: 2,
        },
        layout: [
            {
                name: "Headers",
                kind: "header",
                offset: 0,
                size: 1024,
                entropy: 1.2,
            },
            {
                name: ".text",
                kind: "section",
                offset: 1024,
                size: 2048,
                entropy: 7.6,
            },
            {
                name: "Overlay",
                kind: "overlay",
                offset: 3072,
                size: 1024,
                entropy: 7.9,
            },
        ],
        memory_layout: [
            {
                name: ".text",
                rva: 4096,
                virtual_size: 2048,
                r: true,
                w: true,
                x: true,
            },
        ],
    },
};

describe("static insight", () => {
    it("lists indicators most severe first and filters by severity", () => {
        render(<Indicators data={pe} />);
        const rows = () =>
            screen
                .getAllByRole("row")
                .slice(1)
                .map((r) => within(r).getAllByRole("cell")[2].textContent);
        expect(rows()).toEqual([
            "Import: CreateRemoteThread",
            "String: shell command (1)",
            "ASLR is not enabled",
        ]);
        expect(
            screen.getByRole("link", { name: "T1055" }).getAttribute("href"),
        ).toBe("https://attack.mitre.org/techniques/T1055/");
        fireEvent.click(screen.getAllByRole("checkbox")[0]); // hide high
        expect(rows()).toEqual([
            "String: shell command (1)",
            "ASLR is not enabled",
        ]);
    });
    it("annotates imports, sorts by severity and filters by library", () => {
        render(<ImportsView data={pe} />);
        const names = () =>
            screen
                .getAllByRole("row")
                .slice(1)
                .map((r) => within(r).getAllByRole("cell")[1].textContent);
        expect(names()).toEqual([
            "CreateRemoteThread",
            "GetAsyncKeyState",
            "CloseHandle",
        ]);
        expect(screen.getByText("Code injection.")).toBeTruthy();
        const libraries = screen.getByRole("navigation", { name: "Libraries" });
        fireEvent.click(within(libraries).getByText("user32.dll"));
        expect(names()).toEqual(["GetAsyncKeyState"]);
        fireEvent.click(within(libraries).getByText("All libraries"));
        fireEvent.click(screen.getByLabelText("Flagged only"));
        expect(names()).toEqual(["CreateRemoteThread", "GetAsyncKeyState"]);
    });
    it("draws the file layout and flags packed regions and W+X memory", () => {
        const { container } = render(<FileLayout data={pe} />);
        expect(screen.getByRole("img", { name: /File layout/ })).toBeTruthy();
        expect(
            container.querySelectorAll(".static-layout-bar")[0].children,
        ).toHaveLength(3);
        expect(screen.getAllByText(/packed \/ encrypted\?/)).toHaveLength(2);
        expect(
            container.querySelector(".static-layout-part.is-wx"),
        ).toBeTruthy();
    });
});
