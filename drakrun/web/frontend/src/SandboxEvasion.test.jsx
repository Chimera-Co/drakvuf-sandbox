import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import SandboxEvasion from "./SandboxEvasion.jsx";
import * as evasionApi from "./evasionApi.js";

vi.mock("./evasionApi.js");

const WINDOWS_SANDBOX = {
    id: "win10",
    display_name: "Windows 10 Test",
    platform: "windows",
    available_tools: [
        {
            id: "perdedor",
            display_name: "PERDEDOR",
            options_schema: { full_suite_only: true, options: [] },
        },
        {
            id: "alkhaser",
            display_name: "al-khaser",
            options_schema: {
                full_suite_only: false,
                options: [
                    {
                        name: "sleep_seconds",
                        kind: "integer",
                        label: "Sleep seconds",
                        default: 30,
                        minimum: 1,
                    },
                ],
            },
        },
    ],
};

const LINUX_SANDBOX = {
    id: "linux-test",
    display_name: "Linux Test",
    platform: "linux",
    available_tools: [],
};

function renderPage() {
    return render(
        <MemoryRouter>
            <SandboxEvasion />
        </MemoryRouter>,
    );
}

describe("SandboxEvasion", () => {
    beforeEach(() => {
        vi.resetAllMocks();
    });

    it("derives the tool list entirely from the selected sandbox's available_tools", async () => {
        evasionApi.getSandboxes.mockResolvedValue([
            WINDOWS_SANDBOX,
            LINUX_SANDBOX,
        ]);
        renderPage();

        await waitFor(() =>
            expect(screen.getByText("PERDEDOR")).toBeInTheDocument(),
        );
        expect(screen.getByText("al-khaser")).toBeInTheDocument();

        fireEvent.change(screen.getByLabelText("Sandbox"), {
            target: { value: "linux-test" },
        });

        // Neither tool is hardcoded as always-available: a sandbox whose
        // platform no adapter supports must show zero tools, not a stale
        // Windows tool list.
        await waitFor(() =>
            expect(
                screen.getByText(/No verification tools are available/),
            ).toBeInTheDocument(),
        );
        expect(screen.queryByText("PERDEDOR")).not.toBeInTheDocument();
    });

    it("only shows the Custom options panel for a selected tool under the Custom profile", async () => {
        evasionApi.getSandboxes.mockResolvedValue([WINDOWS_SANDBOX]);
        renderPage();
        await waitFor(() =>
            expect(screen.getByText("PERDEDOR")).toBeInTheDocument(),
        );

        expect(screen.queryByText("Sleep seconds")).not.toBeInTheDocument();

        fireEvent.click(screen.getByLabelText("Custom"));

        await waitFor(() =>
            expect(screen.getByText("Sleep seconds")).toBeInTheDocument(),
        );
        // PERDEDOR has no configurable options - it must get its
        // explanatory note, not fabricated controls.
        expect(
            screen.getByText(/PERDEDOR runs its full check suite/),
        ).toBeInTheDocument();
    });

    it("submits exactly the chosen sandbox/tools/profile to createScan", async () => {
        evasionApi.getSandboxes.mockResolvedValue([WINDOWS_SANDBOX]);
        evasionApi.createScan.mockResolvedValue({
            scan_id: "11111111-1111-4111-8111-111111111111",
        });
        renderPage();
        await waitFor(() =>
            expect(screen.getByText("PERDEDOR")).toBeInTheDocument(),
        );

        fireEvent.click(screen.getByText("Start scan"));

        await waitFor(() => expect(evasionApi.createScan).toHaveBeenCalled());
        const args = evasionApi.createScan.mock.calls[0][0];
        expect(args.sandboxId).toBe("win10");
        expect([...args.tools].sort()).toEqual(["alkhaser", "perdedor"]);
        expect(args.profile).toBe("full");
    });
});
