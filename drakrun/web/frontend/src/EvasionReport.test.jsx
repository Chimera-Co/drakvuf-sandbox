import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { EvasionReport } from "./EvasionReport.jsx";

// The Files tab isn't active by default, so its useEffect never fires in
// these tests, but evasionApi is still mocked defensively in case that
// changes.
vi.mock("./evasionApi.js");

function makeScan({ score, toolResults }) {
    return {
        id: "11111111-1111-4111-8111-111111111111",
        sandbox: {
            id: "win10",
            display_name: "Windows 10 Test",
            platform: "windows",
        },
        options: { profile: "full", tools: toolResults.map((t) => t.tool) },
        time_started: "2024-01-01T00:00:00+00:00",
        time_finished: "2024-01-01T00:10:00+00:00",
        tool_results: toolResults,
        score,
    };
}

describe("EvasionReport", () => {
    it("makes the CHIMERA-score-vs-tool-native distinction visually obvious", () => {
        const scan = makeScan({
            score: {
                chimera_score: 100.0,
                state: "pass",
                primary_tool: "perdedor",
                per_category: { timing: 100.0 },
                tool_scores: {
                    perdedor: {
                        status: "ok",
                        raw_score: "1/1",
                        detected: 0,
                        errored: 0,
                        skipped: 0,
                        weighted_score: 100.0,
                    },
                    alkhaser: {
                        status: "ok",
                        raw_score: "0/1",
                        detected: 1,
                        errored: 0,
                        skipped: 0,
                    },
                },
                rationale: [
                    "CHIMERA score is perdedor's own severity-weighted score.",
                ],
            },
            toolResults: [
                { tool: "perdedor", status: "ok", checks: [] },
                { tool: "alkhaser", status: "ok", checks: [] },
            ],
        });

        render(<EvasionReport scan={scan} />);

        expect(screen.getByText("100.0")).toBeInTheDocument();
        // Only PERDEDOR (primary_tool) is tagged as the CHIMERA score's
        // source - al-khaser's detection must never be implied to
        // contribute to it.
        expect(screen.getByText("CHIMERA score source")).toBeInTheDocument();
        expect(
            screen.getByText(/not scored \(corroborating evidence only\)/),
        ).toBeInTheDocument();
    });

    it("shows an explicit incomplete state instead of a manufactured score", () => {
        const scan = makeScan({
            score: {
                chimera_score: null,
                state: "incomplete",
                primary_tool: null,
                per_category: {},
                tool_scores: {
                    perdedor: {
                        status: "unsupported",
                        raw_score: "0/0",
                        detected: 0,
                        errored: 0,
                        skipped: 0,
                    },
                },
                rationale: [
                    "perdedor did not complete successfully (status=unsupported).",
                ],
            },
            toolResults: [
                { tool: "perdedor", status: "unsupported", checks: [] },
            ],
        });

        render(<EvasionReport scan={scan} />);

        expect(screen.getByText("N/A")).toBeInTheDocument();
        expect(
            screen.getByText(/No CHIMERA score is available/),
        ).toBeInTheDocument();
        expect(screen.getByText("Incomplete")).toBeInTheDocument();
        expect(screen.queryByText("100.0")).not.toBeInTheDocument();
    });
});
