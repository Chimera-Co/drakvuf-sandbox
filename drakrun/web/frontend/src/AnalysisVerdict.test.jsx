import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, act, cleanup, within } from "@testing-library/react";
import { StaticAnalysisTab, VerdictCard } from "./AnalysisVerdict.jsx";
import { getClassification, getStaticReport } from "./api.js";

vi.mock("./api.js");

const ID = "11111111-1111-4111-8111-111111111111";

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
                "Decision score: 0.50 is the malicious threshold. It is not a probability.",
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
            within(screen.getByText("Coverage").closest("tr")).getByText(
                expected,
            ),
        ).toBeTruthy();
        expect(
            within(screen.getByText("YARA").closest("tr")).getByText(yara),
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
