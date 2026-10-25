import { afterEach, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { PipelineStatus } from "./PipelineStatus.jsx";
import { getPipeline } from "./api.js";

vi.mock("./api.js", () => ({ getPipeline: vi.fn() }));
afterEach(() => {
    cleanup();
    vi.clearAllMocks();
});

it("shows one chip per stage with its state", async () => {
    getPipeline.mockResolvedValue({
        active: false,
        stages: [
            {
                id: "static",
                label: "Static analysis",
                state: "done",
                detail: "full",
            },
            {
                id: "dynamic",
                label: "Dynamic analysis (VM)",
                state: "failed",
                detail: "guest crashed",
            },
            {
                id: "intel",
                label: "Threat intel",
                state: "pending",
                detail: "",
            },
        ],
    });
    render(<PipelineStatus analysisId="x" />);
    const list = await screen.findByRole("list", { name: "Analysis stages" });
    expect(list.children).toHaveLength(3);
    expect(screen.getByText("guest crashed")).toBeTruthy();
    expect(screen.getByText(": failed")).toBeTruthy();
    expect(list.children[2].className).toContain("is-pending");
    expect(getPipeline).toHaveBeenCalledTimes(1); // not active: no polling
});
