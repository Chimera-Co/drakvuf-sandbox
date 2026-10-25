import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { EvasionCheckTable } from "./EvasionCheckTable.jsx";

describe("EvasionCheckTable", () => {
    it("groups checks by category and shows each check's own tool", () => {
        const toolResults = [
            {
                tool: "perdedor",
                checks: [
                    {
                        id: "p1",
                        category: "timing",
                        name: "Uptime",
                        description: "d",
                        status: "clean",
                        severity: "low",
                        tool: "perdedor",
                    },
                ],
            },
            {
                tool: "alkhaser",
                checks: [
                    {
                        id: "a1",
                        category: "timing",
                        name: "RDTSC",
                        description: "d",
                        status: "detected",
                        severity: "critical",
                        tool: "alkhaser",
                    },
                ],
            },
        ];
        render(<EvasionCheckTable toolResults={toolResults} />);

        expect(screen.getByText(/Timing \(2\)/)).toBeInTheDocument();
        expect(screen.getByText("perdedor")).toBeInTheDocument();
        expect(screen.getByText("alkhaser")).toBeInTheDocument();
        expect(screen.getByText("detected")).toBeInTheDocument();
        expect(screen.getByText("clean")).toBeInTheDocument();
    });

    it("shows a clear message rather than an empty table when there are no checks", () => {
        render(<EvasionCheckTable toolResults={[]} />);
        expect(
            screen.getByText(/No individual checks were recorded/),
        ).toBeInTheDocument();
    });
});
