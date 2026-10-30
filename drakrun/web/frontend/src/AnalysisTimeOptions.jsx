import { useState } from "react";
import {
    CLOCK_FACTORS,
    DEFAULT_FACTOR,
    MAX_CUSTOM_MIN,
    TIME_PRESETS_MIN,
    formatDuration,
    realTimeoutSeconds,
} from "./analysisTime.js";

/**
 * Analysis time and the two optional accelerations. Renders the form fields the upload reads:
 * timeout (real seconds), clock_scale and sleep_skip. settings is GET /api/analysis-time;
 * until it arrives no clock speed-up is offered (it needs an image that supports it).
 */
export function AnalysisTimeOptions({ windows, settings }) {
    const [preset, setPreset] = useState("10");
    const [customMinutes, setCustomMinutes] = useState(90);
    const [speedUp, setSpeedUp] = useState(false);
    const [factor, setFactor] = useState(DEFAULT_FACTOR);
    const [sleepSkip, setSleepSkip] = useState(false);

    const maxTimeoutS = settings?.max_timeout_s ?? 86400;
    const speedUpAvailable = windows && Boolean(settings?.clock_scale_enabled);
    const factors = CLOCK_FACTORS.filter(
        (f) => f <= (settings?.clock_scale_max ?? 1),
    );
    const skipAboveS = (settings?.sleep_skip_above_ms ?? 10000) / 1000;
    const skipToS = (settings?.sleep_skip_to_ms ?? 1000) / 1000;

    const clockScale = speedUpAvailable && speedUp ? factor : 1;
    const guestMinutes =
        preset === "custom"
            ? Math.min(
                  MAX_CUSTOM_MIN,
                  Math.max(1, Math.round(customMinutes) || 1),
              )
            : Number(preset);
    const realSeconds = realTimeoutSeconds(guestMinutes, clockScale);
    const presets = TIME_PRESETS_MIN.filter(
        (minutes) => realTimeoutSeconds(minutes, clockScale) <= maxTimeoutS,
    );

    return (
        <div className="mb-3">
            <label htmlFor="form-analysis-time" className="form-label">
                Analysis time
            </label>
            <div className="d-flex gap-2">
                <select
                    id="form-analysis-time"
                    className="form-select"
                    value={preset}
                    onChange={(ev) => setPreset(ev.target.value)}
                >
                    {presets.map((minutes) => (
                        <option key={minutes} value={String(minutes)}>
                            {formatDuration(minutes * 60)}
                        </option>
                    ))}
                    <option value="custom">Custom…</option>
                </select>
                {preset === "custom" && (
                    <div className="input-group" style={{ maxWidth: "12rem" }}>
                        <input
                            type="number"
                            className="form-control"
                            aria-label="Custom analysis time in minutes"
                            min="1"
                            max={MAX_CUSTOM_MIN}
                            value={customMinutes}
                            onChange={(ev) =>
                                setCustomMinutes(+ev.target.value)
                            }
                        />
                        <span className="input-group-text">min</span>
                    </div>
                )}
            </div>
            <input type="hidden" name="timeout" value={realSeconds} />
            {speedUpAvailable && (
                <>
                    <div className="form-check mt-2">
                        <input
                            className="form-check-input"
                            id="clock-speed-up"
                            type="checkbox"
                            checked={speedUp}
                            onChange={(ev) => setSpeedUp(ev.target.checked)}
                        />
                        <label
                            className="form-check-label"
                            htmlFor="clock-speed-up"
                        >
                            Speed up the guest clock
                        </label>
                    </div>
                    {speedUp && (
                        <select
                            className="form-select form-select-sm mt-1 ms-4"
                            style={{ maxWidth: "16rem" }}
                            aria-label="Clock speed-up factor"
                            value={factor}
                            onChange={(ev) => setFactor(+ev.target.value)}
                        >
                            {factors.map((f) => (
                                <option key={f} value={f}>
                                    {f}× (1 h passes in{" "}
                                    {formatDuration(3600 / f)})
                                </option>
                            ))}
                        </select>
                    )}
                    {clockScale > 1 && (
                        <input
                            type="hidden"
                            name="clock_scale"
                            value={clockScale}
                        />
                    )}
                </>
            )}
            {windows && (
                <div className="form-check mt-2">
                    <input
                        className="form-check-input"
                        id="sleep-skip"
                        type="checkbox"
                        name="sleep_skip"
                        value="1"
                        checked={sleepSkip}
                        onChange={(ev) => setSleepSkip(ev.target.checked)}
                    />
                    <label className="form-check-label" htmlFor="sleep-skip">
                        Shorten long sleeps (experimental){" "}
                        <span className="text-muted">
                            (over {skipAboveS} s, to {skipToS} s, in the
                            sample&apos;s own processes)
                        </span>
                    </label>
                </div>
            )}
            <div className="form-text">
                {clockScale > 1
                    ? `The VM runs for ${formatDuration(realSeconds)}; its clock covers ${formatDuration(realSeconds * clockScale)}.`
                    : `The VM runs for ${formatDuration(realSeconds)}.`}
                {windows &&
                    (speedUpAvailable
                        ? " Samples can detect a sped-up clock or shortened sleeps: both stay off unless you turn them on."
                        : " Samples can detect shortened sleeps: it stays off unless you turn it on.")}
            </div>
        </div>
    );
}
