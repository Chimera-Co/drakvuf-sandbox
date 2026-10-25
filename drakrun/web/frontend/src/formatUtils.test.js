import { describe, expect, it } from "vitest";
import { formatSandbox } from "./formatUtils.js";

describe("formatSandbox", () => {
    it("names the guest OS and VM", () => {
        expect(
            formatSandbox({ options: { guest_os: "linux" }, vm_id: 2 }),
        ).toBe("Debian 12 (Linux) · vm-2");
        expect(
            formatSandbox({ options: { guest_os: "windows" }, vm_id: 1 }),
        ).toBe("Windows 10 · vm-1");
    });

    it("treats analyses without guest_os as Windows", () => {
        expect(formatSandbox({ options: {} })).toBe("Windows 10");
    });
});
