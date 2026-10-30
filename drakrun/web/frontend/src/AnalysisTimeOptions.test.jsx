import { afterEach, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { AnalysisTimeOptions } from "./AnalysisTimeOptions.jsx";
import { formatDuration, realTimeoutSeconds } from "./analysisTime.js";

afterEach(cleanup);

const ENABLED = {
    max_timeout_s: 86400,
    clock_scale_enabled: true,
    clock_scale_max: 60,
    sleep_skip_above_ms: 10000,
    sleep_skip_to_ms: 1000,
};

const field = (name) => document.querySelector(`[name="${name}"]`);

it("formats durations", () => {
    expect(formatDuration(30)).toBe("30 s");
    expect(formatDuration(300)).toBe("5 min");
    expect(formatDuration(3600)).toBe("1 h");
    expect(formatDuration(5400)).toBe("1 h 30 min");
    expect(formatDuration(86400)).toBe("24 h");
});

it("runs the VM for the guest time divided by the speed-up, at least a minute", () => {
    expect(realTimeoutSeconds(60, 1)).toBe(3600);
    expect(realTimeoutSeconds(60, 12)).toBe(300);
    expect(realTimeoutSeconds(600, 12)).toBe(3000);
    expect(realTimeoutSeconds(5, 60)).toBe(60);
});

it("defaults to 10 minutes with both accelerations off", () => {
    render(<AnalysisTimeOptions windows settings={ENABLED} />);
    expect(field("timeout").value).toBe("600");
    expect(field("clock_scale")).toBeNull();
    expect(screen.getByLabelText(/Shorten long sleeps/).checked).toBe(false);
    expect(screen.getByLabelText("Speed up the guest clock").checked).toBe(
        false,
    );
});

it("offers analysis times up to 24 hours", () => {
    render(<AnalysisTimeOptions windows settings={ENABLED} />);
    fireEvent.change(screen.getByLabelText("Analysis time"), {
        target: { value: "600" },
    });
    expect(field("timeout").value).toBe("36000");
    fireEvent.change(screen.getByLabelText("Analysis time"), {
        target: { value: "1440" },
    });
    expect(field("timeout").value).toBe("86400");
});

it("speeds up the clock: 1 h of guest time in 5 real minutes at 12x", () => {
    render(<AnalysisTimeOptions windows settings={ENABLED} />);
    fireEvent.change(screen.getByLabelText("Analysis time"), {
        target: { value: "60" },
    });
    fireEvent.click(screen.getByLabelText("Speed up the guest clock"));
    expect(field("clock_scale").value).toBe("12");
    expect(field("timeout").value).toBe("300");
    expect(
        screen.getByText(/runs for 5 min; its clock covers 1 h/),
    ).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Clock speed-up factor"), {
        target: { value: "60" },
    });
    expect(field("clock_scale").value).toBe("60");
    expect(field("timeout").value).toBe("60");
});

it("takes a custom time in minutes", () => {
    render(<AnalysisTimeOptions windows settings={ENABLED} />);
    fireEvent.change(screen.getByLabelText("Analysis time"), {
        target: { value: "custom" },
    });
    fireEvent.change(screen.getByLabelText("Custom analysis time in minutes"), {
        target: { value: "45" },
    });
    expect(field("timeout").value).toBe("2700");
});

it("has no accelerations for Linux", () => {
    render(<AnalysisTimeOptions windows={false} settings={ENABLED} />);
    expect(screen.queryByLabelText("Speed up the guest clock")).toBeNull();
    expect(field("sleep_skip")).toBeNull();
    expect(field("clock_scale")).toBeNull();
    expect(field("timeout").value).toBe("600");
});

it("offers no speed-up when the server does not, or before its settings arrive", () => {
    render(
        <AnalysisTimeOptions
            windows
            settings={{ ...ENABLED, clock_scale_enabled: false }}
        />,
    );
    expect(screen.queryByLabelText("Speed up the guest clock")).toBeNull();
    expect(screen.getByLabelText(/Shorten long sleeps/)).toBeTruthy();
    cleanup();
    render(<AnalysisTimeOptions windows settings={null} />);
    expect(screen.queryByLabelText("Speed up the guest clock")).toBeNull();
    expect(field("timeout").value).toBe("600");
});

it("leaves out analysis times above the server's limit", () => {
    render(
        <AnalysisTimeOptions
            windows
            settings={{
                ...ENABLED,
                clock_scale_enabled: false,
                max_timeout_s: 3600,
            }}
        />,
    );
    const options = [...screen.getByLabelText("Analysis time").options].map(
        (o) => o.value,
    );
    expect(options).toEqual(["5", "10", "20", "30", "60", "custom"]);
});
