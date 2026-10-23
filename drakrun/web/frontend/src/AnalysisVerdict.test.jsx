import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
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
        expect(await screen.findByText("combined score 0.01")).toBeTruthy();
        expect(screen.getByText("dynamic")).toBeTruthy();
        expect(screen.getByText("suspicious")).toBeTruthy();
        expect(screen.getByText("TLS callbacks")).toBeTruthy();
    });

    it("says when the run is not classified yet", async () => {
        getClassification.mockRejectedValue({ response: { status: 404 } });
        render(<VerdictCard analysisId={ID} />);
        expect(await screen.findByText("Not classified yet.")).toBeTruthy();
    });

    it("shows a model error as unknown", async () => {
        getClassification.mockResolvedValue({
            schema: "chimera-verdict/1",
            label: "unknown",
            error: "timed out",
        });
        render(<VerdictCard analysisId={ID} />);
        expect(await screen.findByText("timed out")).toBeTruthy();
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
