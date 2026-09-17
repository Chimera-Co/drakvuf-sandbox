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
    pass: "#5c6a00", // --chimera-green-ink
    warn: "#7d5f00", // --chimera-yellow-ink
    fail: "#c32b28", // --chimera-red-ink
    incomplete: "#586e75", // --chimera-base01 (muted)
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
                    stroke="#1e6fa8"
                    fill="#1e6fa8"
                    fillOpacity={0.35}
                />
                <Tooltip />
            </RadarChart>
        </ResponsiveContainer>
    );
}

export function ScoreTrend({ runs }) {
    const data = (runs || [])
        .filter((r) => typeof r.score?.chimera_score === "number")
        .slice()
        .sort((a, b) => new Date(a.time_started) - new Date(b.time_started))
        .map((r) => ({
            time: r.time_started,
            score: r.score.chimera_score,
        }));
    if (data.length === 0) {
        return (
            <div className="text-muted small">
                No completed runs with a CHIMERA score yet.
            </div>
        );
    }
    return (
        <ResponsiveContainer width="100%" height={220}>
            <LineChart data={data}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis
                    dataKey="time"
                    tickFormatter={(t) => formatDate(t).slice(0, 10)}
                />
                <YAxis domain={[0, 100]} />
                <Tooltip labelFormatter={(t) => formatDate(t)} />
                <Line
                    type="monotone"
                    dataKey="score"
                    stroke="#1e6fa8"
                    dot
                    connectNulls
                />
            </LineChart>
        </ResponsiveContainer>
    );
}
