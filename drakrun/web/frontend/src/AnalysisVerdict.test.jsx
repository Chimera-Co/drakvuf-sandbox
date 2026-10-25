import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import {
    render,
    screen,
    act,
    cleanup,
    within,
    fireEvent,
} from "@testing-library/react";
import {
    DeepSection,
    StaticAnalysisTab,
    VerdictCard,
} from "./AnalysisVerdict.jsx";
import { getClassification, getDeepStatic, getStaticReport } from "./api.js";

vi.mock("./api.js");

const ID = "11111111-1111-4111-8111-111111111111";

// The deep pass is a separate request; unless a test says otherwise it has not run yet.
beforeEach(() => {
    getDeepStatic.mockRejectedValue({ response: { status: 404 } });
});

describe("VerdictCard", () => {
    it("shows the combined verdict and each component", async () => {
        getClassification.mockResolvedValue({
            schema: "chimera-verdict/1",
            label: "benign",
            score: 0.0064,
            family: null,
            model: "chimera-fusion",
            model_version: "0.1",
            explanation: [],
            components: {
                dynamic: {
                    label: "benign",
                    score: 0.0029,
                    explanation: ["1 registry value writes"],
                },
                static: {
                    label: "suspicious",
                    score: 0.6,
                    explanation: ["TLS callbacks"],
                },
            },
        });
        render(<VerdictCard analysisId={ID} />);
        expect(
            await screen.findByText("combined decision score 0.01"),
        ).toBeTruthy();
        expect(
            screen.getByText(
                "Scores are not probabilities until the model is calibrated; 0.50 is the malicious threshold.",
            ),
        ).toBeTruthy();
        expect(screen.getByText("decision score 0.60")).toBeTruthy();
        expect(screen.getByText("dynamic")).toBeTruthy();
        expect(screen.getByText("suspicious")).toBeTruthy();
        expect(screen.getByText("TLS callbacks")).toBeTruthy();
    });

    it("says when the run is not classified yet", async () => {
        getClassification.mockRejectedValue({ response: { status: 404 } });
        render(<VerdictCard analysisId={ID} />);
        expect(
            await screen.findByText(/Not classified yet: waiting/),
        ).toBeTruthy();
    });

    it("shows a model error as unknown", async () => {
        getClassification.mockResolvedValue({
            schema: "chimera-verdict/1",
            label: "unknown",
            error: "timed out",
        });
        render(<VerdictCard analysisId={ID} />);
        expect(await screen.findByText("timed out")).toBeTruthy();
        expect(screen.getByText("no verdict")).toBeTruthy();
    });
});

describe("StaticAnalysisTab", () => {
    it("lists findings", async () => {
        getStaticReport.mockResolvedValue({
            schema: "chimera-static/1",
            level: "clean",
            score: 8,
            type: { format: "pe", platform: "windows", arch: "x86_64" },
            file: { size: 10, md5: "m", sha1: "s" },
            findings: [
                {
                    id: "x",
                    title: "Imports anti debug APIs",
                    severity: "low",
                    evidence: "IsDebuggerPresent",
                    attack: ["T1622"],
                },
            ],
            errors: [{ stage: "yara", error: "no YARA rules" }],
        });
        render(<StaticAnalysisTab analysisId={ID} />);
        expect(await screen.findByText("Imports anti debug APIs")).toBeTruthy();
        expect(screen.getByText("T1622")).toBeTruthy();
        expect(screen.getByText("pe / windows / x86_64")).toBeTruthy();
        expect(screen.getByText("yara: no YARA rules")).toBeTruthy();
    });

    it("shows a failed static run", async () => {
        getStaticReport.mockResolvedValue({
            schema: "chimera-static/1",
            error: "no static.json written",
        });
        render(<StaticAnalysisTab analysisId={ID} />);
        expect(
            await screen.findByText(
                "Static analysis failed: no static.json written",
            ),
        ).toBeTruthy();
    });
});

afterEach(() => {
    cleanup();
    vi.useRealTimers();
    vi.resetAllMocks();
});

describe.each([
    [
        "verdict",
        VerdictCard,
        getClassification,
        /Not classified yet: waiting/,
        "Not classified yet.",
    ],
    [
        "static",
        StaticAnalysisTab,
        getStaticReport,
        /No static analysis yet: waiting/,
        "No static analysis for this analysis (static analysis was off, or it has not finished).",
    ],
])("%s polling", (_name, Component, loader, waiting, missing) => {
    it("loads results after a 404 and stops polling", async () => {
        vi.useFakeTimers();
        loader
            .mockRejectedValueOnce({ response: { status: 404 } })
            .mockResolvedValue({ error: "result arrived" });
        render(<Component analysisId={ID} />);
        await act(async () => {});
        expect(screen.getByText(waiting)).toBeTruthy();
        await act(async () => {
            await vi.advanceTimersByTimeAsync(5000);
        });
        expect(screen.getByText(/result arrived/)).toBeTruthy();
        await act(async () => {
            await vi.advanceTimersByTimeAsync(900000);
        });
        expect(loader).toHaveBeenCalledTimes(2);
    });

    it("does not retry non-404 errors", async () => {
        vi.useFakeTimers();
        loader.mockRejectedValue(new Error("unavailable"));
        render(<Component analysisId={ID} />);
        await act(async () => {});
        expect(screen.getByText(/Error: Error: unavailable/)).toBeTruthy();
        await act(async () => {
            await vi.advanceTimersByTimeAsync(900000);
        });
        expect(loader).toHaveBeenCalledTimes(1);
    });

    it("stops after fifteen minutes", async () => {
        vi.useFakeTimers();
        loader.mockRejectedValue({ response: { status: 404 } });
        render(<Component analysisId={ID} />);
        await act(async () => {});
        await act(async () => {
            await vi.advanceTimersByTimeAsync(900000);
        });
        expect(screen.getByText(missing)).toBeTruthy();
        const calls = loader.mock.calls.length;
        await act(async () => {
            await vi.advanceTimersByTimeAsync(30000);
        });
        expect(loader).toHaveBeenCalledTimes(calls);
    });

    it("cleans up on analysis changes and unmount", async () => {
        vi.useFakeTimers();
        let resolveOld;
        loader
            .mockImplementationOnce(
                () =>
                    new Promise((resolve) => {
                        resolveOld = resolve;
                    }),
            )
            .mockRejectedValue({ response: { status: 404 } });
        const view = render(<Component analysisId={ID} />);
        view.rerender(<Component analysisId="new-id" />);
        await act(async () => {
            resolveOld({ error: "stale result" });
        });
        expect(screen.queryByText(/stale result/)).toBeNull();
        expect(screen.getByText(waiting)).toBeTruthy();
        view.unmount();
        await act(async () => {
            await vi.advanceTimersByTimeAsync(900000);
        });
        expect(loader).toHaveBeenCalledTimes(2);
        expect(vi.getTimerCount()).toBe(0);
    });
});

it("orders and styles verdict and component warnings first", async () => {
    const lines = [
        "ordinary evidence",
        "No verdict available",
        "No static verdict available",
        "Static analysis failed: timeout",
        "Notice: No benign verdict possible",
    ];
    getClassification.mockResolvedValue({
        label: "unknown",
        explanation: lines,
        components: { static: { explanation: lines } },
    });
    render(<VerdictCard analysisId={ID} />);
    await screen.findByText("static");
    for (const list of screen.getAllByRole("list")) {
        const items = within(list).getAllByRole("listitem");
        expect(items.map((item) => item.textContent)).toEqual([
            ...lines.slice(1),
            lines[0],
        ]);
        items
            .slice(0, 4)
            .forEach((item) =>
                expect(item.className).toBe(
                    "text-warning-emphasis fw-semibold",
                ),
            );
    }
});

it.each([
    [
        { complete: true, type_plugin: "pe", failed_stages: [] },
        "complete",
        "42 rules (community @ abcdef1)",
    ],
    [
        { complete: false, type_plugin: null, failed_stages: ["yara"] },
        "partial: no parser for pe files; failed: yara",
        "42 rules (community @ abcdef1) - scan did not run",
    ],
])(
    "reports static coverage and YARA sources",
    async (coverage, expected, yara) => {
        getStaticReport.mockResolvedValue({
            type: { format: "pe" },
            coverage,
            universal: {
                yara_ruleset: {
                    rules: 42,
                    sources: [
                        {
                            name: "community",
                            commit: "abcdef123456",
                            licence: "MIT",
                        },
                    ],
                },
            },
        });
        render(<StaticAnalysisTab analysisId={ID} />);
        expect(await screen.findByText(expected)).toBeTruthy();
        expect(
            within(screen.getByRole("region", { name: "Coverage" })).getByText(
                expected,
            ),
        ).toBeTruthy();
        expect(
            within(
                screen.getByRole("region", { name: "YARA ruleset" }),
            ).getByText(yara),
        ).toBeTruthy();
    },
);

it.each([
    [undefined, "no rules"],
    [{ rules: null, note: "rules unavailable" }, "rules unavailable"],
])(
    "handles missing rules and older coverage",
    async (yara_ruleset, expected) => {
        getStaticReport.mockResolvedValue({ universal: { yara_ruleset } });
        render(<StaticAnalysisTab analysisId={ID} />);
        expect(
            await screen.findByText("not reported (older analyzer)"),
        ).toBeTruthy();
        expect(screen.getByText(expected)).toBeTruthy();
    },
);

describe("static hashes", () => {
    it("shows hashes and copies a value", async () => {
        getStaticReport.mockResolvedValue({
            file: {
                sha256: "sha-value",
                ssdeep: "ss-value",
                tlsh: "tls-value",
            },
            pe: { imphash: "imp-value" },
        });
        const writeText = vi.fn().mockResolvedValue();
        Object.defineProperty(navigator, "clipboard", {
            configurable: true,
            value: { writeText },
        });
        render(<StaticAnalysisTab analysisId={ID} />);
        const block = await screen.findByRole("region", { name: "Hashes" });
        for (const value of ["sha-value", "ss-value", "tls-value", "imp-value"])
            expect(within(block).getByText(value)).toBeTruthy();
        fireEvent.click(screen.getByRole("button", { name: "Copy SHA-256" }));
        expect(await screen.findByText("Copied")).toBeTruthy();
        expect(writeText).toHaveBeenCalledWith("sha-value");
    });
    it("shows missing hashes and handles unavailable clipboard", async () => {
        getStaticReport.mockResolvedValue({ file: { sha256: "sha-value" } });
        Object.defineProperty(navigator, "clipboard", {
            configurable: true,
            value: undefined,
        });
        render(<StaticAnalysisTab analysisId={ID} />);
        await screen.findByRole("region", { name: "Hashes" });
        expect(screen.getAllByText("not computed")).toHaveLength(3);
        fireEvent.click(screen.getByRole("button", { name: "Copy SHA-256" }));
        expect(await screen.findByText(/Copy unavailable/)).toBeTruthy();
    });
});

describe("deep pass", () => {
    it("lists capa capabilities and FLOSS strings", async () => {
        getDeepStatic.mockResolvedValue({
            schema: "chimera-deep/1",
            errors: [{ stage: "floss", error: "timed out after 90s" }],
            capa: {
                version: "7.4.0",
                rules_total: 1,
                library_signatures: false,
                rules: [
                    {
                        name: "inject thread",
                        namespace: "host-interaction/process/inject",
                        attack: [{ id: "T1055", tactic: "Defense Evasion" }],
                        mbc: [{ id: "E1055" }],
                    },
                ],
            },
            floss: {
                version: "3.2.0",
                stack: { count: 1, sample: ["kernel32.dll"] },
                tight: { count: 0, sample: [] },
                decoded: { count: 0, sample: [] },
            },
        });
        render(<DeepSection analysisId={ID} />);
        const block = await screen.findByRole("region", {
            name: "Capabilities",
        });
        expect(within(block).getByText("inject thread")).toBeTruthy();
        expect(within(block).getByText("T1055")).toBeTruthy();
        expect(within(block).getByText(/no signatures/)).toBeTruthy();
        expect(within(block).getByText("Stack strings (1)")).toBeTruthy();
        expect(
            within(block).getByText("floss: timed out after 90s"),
        ).toBeTruthy();
    });

    it("waits while the deep pass has not run", async () => {
        getDeepStatic.mockRejectedValue({ response: { status: 404 } });
        render(<DeepSection analysisId={ID} />);
        expect(
            await screen.findByText(/capa and FLOSS run after/),
        ).toBeTruthy();
    });

    it("is shown only for PE and ELF files", async () => {
        getDeepStatic.mockRejectedValue({ response: { status: 404 } });
        getStaticReport.mockResolvedValue({ type: { format: "pdf" } });
        render(<StaticAnalysisTab analysisId={ID} />);
        await screen.findByText("Findings (0)");
        expect(
            screen.queryByRole("region", { name: "Capabilities" }),
        ).toBeNull();
    });
});
