import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { MobsfView } from "./MobsfView.jsx";
import { getMobsf } from "../api.js";
vi.mock("../api.js");
afterEach(() => {
    cleanup();
    vi.resetAllMocks();
});

describe("MobSF view", () => {
    it("shows the score, dangerous permissions first and findings", async () => {
        getMobsf.mockResolvedValue({
            schema: "chimera-mobsf/1",
            image: "docker.io/opensecurity/mobile-security-framework-mobsf:v4.5.3",
            error: null,
            app: { app_name: "Flashlight", package_name: "com.example.light" },
            security_score: 41,
            counts: { high: 1, warning: 0, info: 0 },
            findings: [
                {
                    title: "App can read SMS",
                    severity: "high",
                    section: "permissions",
                },
            ],
            permissions: [
                {
                    name: "android.permission.READ_SMS",
                    status: "dangerous",
                    info: "read SMS",
                },
                {
                    name: "android.permission.CAMERA",
                    status: "normal",
                    info: "camera",
                },
            ],
            permissions_total: 2,
            trackers: [],
            code_findings: [],
            manifest_findings: [],
            domains: ["c2.example"],
            urls: [],
        });
        render(<MobsfView analysisId="x" />);
        expect(await screen.findByText("41/100")).toBeTruthy();
        expect(screen.getByText("1 dangerous of 2")).toBeTruthy();
        const perms = screen.getByRole("table", {
            name: "Android permissions",
        });
        expect(within(perms).getAllByRole("row")[1].textContent).toContain(
            "READ_SMS",
        );
        expect(screen.getByText("c2.example")).toBeTruthy();
    });

    it("reports a failed scan instead of empty tables", async () => {
        getMobsf.mockResolvedValue({
            schema: "chimera-mobsf/1",
            error: "MobSF timed out",
        });
        render(<MobsfView analysisId="x" />);
        expect(await screen.findByText(/MobSF timed out/)).toBeTruthy();
    });
});
