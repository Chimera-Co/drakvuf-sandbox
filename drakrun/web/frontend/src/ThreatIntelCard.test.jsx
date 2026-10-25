import { afterEach, expect, it, vi } from "vitest";
import {
    cleanup,
    fireEvent,
    render,
    screen,
    waitFor,
} from "@testing-library/react";
import axios from "axios";
import { ThreatIntelCard } from "./ThreatIntelCard.jsx";
vi.mock("axios", () => ({ default: { get: vi.fn() } }));
afterEach(() => {
    cleanup();
    vi.clearAllMocks();
});
const payload = {
    feeds: [
        {
            name: "synthetic",
            fetched_at: "2026-01-01",
            expires_at: "2026-01-02",
            stale: false,
        },
    ],
    matches: [],
    suppressed: [],
};
it("shows missing offline feeds without requests", () => {
    render(<ThreatIntelCard analysisId="test" isOffline />);
    expect(screen.getByText("Offline feeds missing")).toBeTruthy();
    expect(axios.get).not.toHaveBeenCalled();
});
it("keeps a zero-match result distinct from a benign verdict", () => {
    render(<ThreatIntelCard stage={{ status: "ok", payload }} />);
    expect(
        screen.getByText(
            /No match in the offline feeds.*not a verdict of benign/,
        ),
    ).toBeTruthy();
    expect(screen.getByText("synthetic: fresh").className).toContain(
        "bg-success",
    );
});
it("shows stale matches and copies references without creating links", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: { writeText },
    });
    render(
        <ThreatIntelCard
            stage={{
                status: "stale",
                payload: {
                    ...payload,
                    feeds: [{ ...payload.feeds[0], stale: true }],
                    suppressed: [{}],
                    matches: [
                        {
                            indicator: "evil.example",
                            type: "domain",
                            observed_in: "dynamic",
                            feed: "synthetic",
                            malware_family: "fixture",
                            tags: ["test"],
                            reference: "https://reference.invalid/<script>",
                            stale: true,
                        },
                    ],
                },
            }}
        />,
    );
    expect(screen.getByText("synthetic: stale").className).toContain(
        "bg-warning",
    );
    expect(screen.getByText("evil.example").className).toContain(
        "font-monospace",
    );
    expect(screen.getByText(/1 matches suppressed/)).toBeTruthy();
    expect(screen.queryByRole("link")).toBeNull();
    fireEvent.click(screen.getByText("Copy reference"));
    await waitFor(() =>
        expect(writeText).toHaveBeenCalledWith(
            "https://reference.invalid/<script>",
        ),
    );
});
it("loads the saved stage from the local API", async () => {
    axios.get.mockResolvedValue({ data: { status: "ok", payload } });
    render(<ThreatIntelCard analysisId="test" />);
    await screen.findByText("synthetic: fresh");
    expect(axios.get).toHaveBeenCalledWith("/intel/test", expect.any(Object));
});
it("shows individual missing feeds beside successful feeds", () => {
    render(
        <ThreatIntelCard
            stage={{
                status: "ok",
                payload: { ...payload, failures: [{ name: "missing-feed" }] },
            }}
        />,
    );
    expect(screen.getByText("missing-feed: missing").className).toContain(
        "bg-secondary",
    );
});
