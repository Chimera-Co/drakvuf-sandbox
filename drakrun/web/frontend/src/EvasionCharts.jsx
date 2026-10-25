import {
    RadialBarChart,
    RadialBar,
    PolarAngleAxis,
    RadarChart,
    PolarGrid,
    PolarRadiusAxis,
    Radar,
    ResponsiveContainer,
    LineChart,
    Line,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    Legend,
} from "recharts";
import { formatDate } from "./formatUtils.js";

/**
 * Every chart here renders a number the backend already computed
 * (EvasionScore.chimera_score / per_category / a run's own score) - none of
 * them derive, average, or invent a number of their own. A ScoreGauge/
 * CategoryRadar with nothing to plot (chimera_score is null, or
 * per_category is empty because the scan is incomplete) renders an explicit
 * "not available" message instead of a misleading zero-valued chart.
 */

const SCORE_COLORS = {
    pass: "var(--chimera-green-ink)",
    warn: "var(--chimera-yellow-ink)",
    fail: "var(--chimera-red-ink)",
    incomplete: "var(--chimera-text-muted)",
};

export function ScoreGauge({ score, state }) {
    if (typeof score !== "number") {
        return (
            <div className="text-center text-muted py-4">
                <div className="h3 mb-1">N/A</div>
                <div className="small">
                    No CHIMERA score is available for this scan
                </div>
            </div>
        );
    }
    const color = SCORE_COLORS[state] || SCORE_COLORS.incomplete;
    const data = [{ name: "score", value: score, fill: color }];
    return (
        <div style={{ position: "relative" }}>
            <ResponsiveContainer width="100%" height={200}>
                <RadialBarChart
                    innerRadius="70%"
                    outerRadius="100%"
                    data={data}
                    startAngle={90}
                    endAngle={-270}
                >
                    <PolarAngleAxis
                        type="number"
                        domain={[0, 100]}
                        angleAxisId={0}
                        tick={false}
                    />
                    <RadialBar background dataKey="value" cornerRadius={8} />
                </RadialBarChart>
            </ResponsiveContainer>
            <div
                className="text-center"
                style={{
                    position: "absolute",
                    top: "50%",
                    left: 0,
                    right: 0,
                    transform: "translateY(-50%)",
                    pointerEvents: "none",
                }}
            >
                <div className="h3 mb-0">{score.toFixed(1)}</div>
                <div className="small text-muted">/ 100</div>
            </div>
        </div>
    );
}

export const CATEGORY_LABELS = {
    environment_artifact: "Environment artifact",
    timing: "Timing",
    behavioural_interaction: "Behavioural interaction",
    design_specific: "Design-specific",
};

export function CategoryRadar({ perCategory }) {
    const entries = Object.entries(perCategory || {});
    if (entries.length === 0) {
        return (
            <div className="text-muted small">
                No per-category CHIMERA score is available for this scan.
            </div>
        );
    }
    const data = entries.map(([category, score]) => ({
        category: CATEGORY_LABELS[category] || category,
        score,
    }));
    return (
        <ResponsiveContainer width="100%" height={260}>
            <RadarChart data={data} outerRadius="75%">
                <PolarGrid />
                <PolarAngleAxis dataKey="category" />
                <PolarRadiusAxis domain={[0, 100]} />
                <Radar
                    name="CHIMERA score"
                    dataKey="score"
                    stroke="var(--chimera-chart-1)"
                    fill="var(--chimera-chart-1)"
                    fillOpacity={0.35}
                />
                <Tooltip />
            </RadarChart>
        </ResponsiveContainer>
    );
}

// One line per sandbox: Windows blue, Linux orange, others from the palette
const PLATFORM_COLORS = {
    windows: "var(--chimera-chart-1)",
    linux: "var(--chimera-chart-5)",
};
const EXTRA_COLORS = [
    "var(--chimera-chart-3)",
    "var(--chimera-chart-4)",
    "var(--chimera-chart-2)",
    "var(--chimera-chart-6)",
];

function sandboxSeries(runs) {
    const series = new Map();
    for (const r of runs) {
        const sandbox = r.sandbox || {};
        const key = sandbox.id || sandbox.platform || "unknown";
        if (!series.has(key)) {
            const name =
                sandbox.display_name || sandbox.id || "Unknown sandbox";
            series.set(key, {
                key,
                name: sandbox.platform ? `${name} (${sandbox.platform})` : name,
                platform: sandbox.platform,
            });
        }
    }
    const used = new Set();
    let extra = 0;
    for (const s of series.values()) {
        const preferred = PLATFORM_COLORS[s.platform];
        if (preferred && !used.has(preferred)) {
            s.color = preferred;
        } else {
            s.color = EXTRA_COLORS[extra++ % EXTRA_COLORS.length];
        }
        used.add(s.color);
    }
    return [...series.values()];
}

export function ScoreTrend({ runs }) {
    const scored = (runs || [])
        .filter((r) => typeof r.score?.chimera_score === "number")
        .slice()
        .sort((a, b) => new Date(a.time_started) - new Date(b.time_started));
    if (scored.length === 0) {
        return (
            <div className="text-muted small">
                No completed runs with a CHIMERA score yet.
            </div>
        );
    }
    const series = sandboxSeries(scored);
    const keyOf = (r) => r.sandbox?.id || r.sandbox?.platform || "unknown";
    const data = scored.map((r) => ({
        time: new Date(r.time_started).getTime(),
        [keyOf(r)]: r.score.chimera_score,
    }));
    return (
        <ResponsiveContainer width="100%" height={240}>
            <LineChart data={data}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis
                    dataKey="time"
                    type="number"
                    scale="time"
                    domain={["dataMin", "dataMax"]}
                    tickFormatter={(t) => formatDate(new Date(t)).slice(0, 10)}
                />
                <YAxis domain={[0, 100]} />
                <Tooltip labelFormatter={(t) => formatDate(new Date(t))} />
                <Legend />
                {series.map((s) => (
                    <Line
                        key={s.key}
                        type="monotone"
                        dataKey={s.key}
                        name={s.name}
                        stroke={s.color}
                        strokeWidth={2}
                        dot={{ r: 3, fill: s.color }}
                        connectNulls
                    />
                ))}
            </LineChart>
        </ResponsiveContainer>
    );
}
