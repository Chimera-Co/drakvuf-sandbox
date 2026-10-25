import { describe, it, expect } from "vitest";
import {
    isScanPending,
    isScanFinal,
    scoreStateLabel,
} from "./evasionStatus.js";

describe("isScanPending / isScanFinal", () => {
    it("treats queued and started as pending", () => {
        expect(isScanPending("queued")).toBe(true);
        expect(isScanPending("started")).toBe(true);
        expect(isScanPending("finished")).toBe(false);
        expect(isScanPending("failed")).toBe(false);
    });

    it("treats finished and failed as final", () => {
        expect(isScanFinal("finished")).toBe(true);
        expect(isScanFinal("failed")).toBe(true);
        expect(isScanFinal("queued")).toBe(false);
        expect(isScanFinal("started")).toBe(false);
    });
});

describe("scoreStateLabel", () => {
    it("labels every known EvasionScore.state value", () => {
        expect(scoreStateLabel("pass")).toBe("Pass");
        expect(scoreStateLabel("warn")).toBe("Warn");
        expect(scoreStateLabel("fail")).toBe("Fail");
        expect(scoreStateLabel("incomplete")).toBe("Incomplete");
    });

    it("falls back to the raw value for an unrecognized state rather than hiding it", () => {
        expect(scoreStateLabel("mystery")).toBe("mystery");
        expect(scoreStateLabel(undefined)).toBe("Unknown");
    });
});
