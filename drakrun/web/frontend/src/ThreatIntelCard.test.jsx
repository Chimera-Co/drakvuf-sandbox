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
vi.mock("axios", () => ({ default: { get: vi.fn(), post: vi.fn() } }));
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

it("groups online results, hides providers without keys and opens VirusTotal detail", () => {
    const vtDomain = {
        provider: "virustotal",
        observable: "evil.example",
        type: "domain",
        origin: "dynamic",
        status: "ok",
        verdict: "malicious",
        detections: { malicious: 54, suspicious: 2, total: 72 },
        family: "fixture",
        tags: [],
        permalink: "https://www.virustotal.com/gui/domain/evil.example",
        details: {
            engines: [
                {
                    engine: "EngineA",
                    category: "malicious",
                    result: "Trojan.X",
                },
            ],
            engines_flagged: 1,
            threat: { label: "trojan.fixture" },
            network: { registrar: "Registrar Inc" },
        },
    };
    render(
        <ThreatIntelCard
            isOffline
            stage={{
                assessment: {
                    label: "malicious",
                    basis: "known malware",
                    reasons: ["Hash match"],
                },
                payload: {
                    online: {
                        connectivity: "online",
                        generated_at: "2026-10-25T10:00:00+00:00",
                        providers: [
                            {
                                id: "virustotal",
                                configured: true,
                                status: "ok",
                                queried: 2,
                            },
                            {
                                id: "otx",
                                configured: false,
                                status: "not_configured",
                                queried: 0,
                            },
                        ],
                        results: [
                            {
                                provider: "malwarebazaar",
                                observable: "a".repeat(64),
                                type: "sha256",
                                origin: "sample",
                                status: "not_found",
                                verdict: "unknown",
                            },
                            vtDomain,
                            {
                                provider: "urlhaus",
                                observable: "evil.example",
                                type: "domain",
                                origin: "dynamic",
                                status: "not_found",
                                verdict: "unknown",
                            },
                            {
                                provider: "otx",
                                observable: "evil.example",
                                type: "domain",
                                status: "not_configured",
                                verdict: "unknown",
                            },
                            {
                                provider: "urlscan",
                                observable: "quiet.example",
                                type: "domain",
                                origin: "static",
                                status: "ok",
                                verdict: "unknown",
                                details: { count: 12, malicious_count: 0 },
                            },
                        ],
                    },
                },
            }}
        />,
    );
    expect(screen.getByText("malicious: known malware")).toBeTruthy();
    expect(screen.getByText("1 flagged")).toBeTruthy();
    expect(screen.getAllByText("Not listed")).toHaveLength(2);
    const table = screen.getByRole("table", {
        name: "Online lookups by indicator",
    });
    const rows = table.querySelectorAll("tbody tr");
    expect(rows[0].textContent).toContain("evil.example"); // flagged first
    expect(rows[0].textContent).toContain("Sample's processes");
    expect(rows[0].textContent).not.toContain("AlienVault OTX"); // no key: not shown per indicator
    expect(rows[1].textContent).toContain("Seen in 12 scans, 0 malicious");
    const link = screen.getByText("Malicious 54/72 · fixture");
    expect(link.tagName).toBe("A");
    expect(link.rel).toBe("noopener noreferrer");
    fireEvent.click(screen.getByText("VirusTotal detail"));
    expect(screen.getByText("trojan.fixture")).toBeTruthy();
    expect(screen.getByText("Trojan.X")).toBeTruthy();
    expect(screen.getByText("Registrar Inc")).toBeTruthy();
    expect(screen.getByLabelText("54 of 72 engines")).toBeTruthy();
});

it("queues an offline re-check", async () => {
    axios.get.mockResolvedValue({ data: { online_enabled: true } });
    axios.post.mockResolvedValue({ data: { status: "queued" } });
    render(
        <ThreatIntelCard
            analysisId="fixture"
            stage={{ status: "unavailable" }}
        />,
    );
    fireEvent.click(screen.getByText("Re-check offline feeds"));
    await waitFor(() =>
        expect(axios.post).toHaveBeenCalledWith("/intel/fixture/recheck"),
    );
    expect(screen.getByText("Re-checking offline feeds").disabled).toBe(true);
});

it("explains disabled online lookups", async () => {
    axios.get.mockResolvedValue({ data: { online_enabled: false } });
    render(<ThreatIntelCard stage={{ status: "unavailable" }} />);
    await screen.findByText(/Online disabled/);
    expect(screen.getByText("Run online lookup").disabled).toBe(true);
});

it("queues an online refresh", async () => {
    axios.get.mockResolvedValue({ data: { online_enabled: true } });
    axios.post.mockResolvedValue({ data: { status: "queued" } });
    render(
        <ThreatIntelCard
            analysisId="fixture"
            stage={{ status: "unavailable" }}
        />,
    );
    await waitFor(() =>
        expect(screen.getByText("Run online lookup").disabled).toBe(false),
    );
    fireEvent.click(screen.getByText("Run online lookup"));
    await waitFor(() =>
        expect(axios.post).toHaveBeenCalledWith("/intel/fixture/refresh"),
    );
    expect(screen.getByText("Online lookup running").disabled).toBe(true);
});
it("shows Maltrail attribution with APT families first", () => {
    const attribution = {
        commit: "abcdef0123",
        committed_at: "2026-10-28T20:00:00+00:00",
        stale: false,
        matches: [
            {
                file: "malware/apt_fixture.txt",
                references: ["https://ref.example/one", "javascript:alert(1)"],
            },
        ],
        families: [
            {
                family: "fixture",
                apt: true,
                category: "malware",
                file: "malware/apt_fixture.txt",
                aliases: ["fixture group"],
                indicators: ["evil.example"],
                observed_in: ["dynamic"],
            },
        ],
    };
    render(
        <ThreatIntelCard
            isOffline
            stage={{ status: "ok", payload: { attribution } }}
        />,
    );
    expect(screen.getByText("fixture")).toBeTruthy();
    expect(screen.getByText("APT")).toBeTruthy();
    expect(screen.getByText("Sample's processes")).toBeTruthy();
    expect(screen.getByText("https://ref.example/one").tagName).toBe("A");
    expect(screen.getByText("javascript:alert(1)").tagName).toBe("DIV");
});
it("lists bare-TLD hits as a weak note, not as a family", () => {
    const attribution = {
        commit: "abcdef0123",
        committed_at: "2026-10-28T20:00:00+00:00",
        stale: false,
        matches: [],
        families: [],
        suspicious_tlds: [
            {
                tld: "cc",
                file: "suspicious/domain.txt",
                indicators: ["c2.example.cc"],
                observed_in: ["dynamic"],
            },
        ],
    };
    render(
        <ThreatIntelCard
            isOffline
            stage={{ status: "ok", payload: { attribution } }}
        />,
    );
    expect(
        screen.getByText(
            "No indicator from the run or the file is in the trails.",
        ),
    ).toBeTruthy();
    expect(
        screen.getByText(
            /Suspicious TLD only \(weak, not an attribution\): \.cc \(c2\.example\.cc\)/,
        ),
    ).toBeTruthy();
    expect(screen.queryByText("domain")).toBeNull();
});
