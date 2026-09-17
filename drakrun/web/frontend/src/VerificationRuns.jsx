import { Link } from "react-router-dom";
import { useEffect, useState } from "react";
import { CanceledError } from "axios";
import { getScanList } from "./evasionApi.js";
import { AnalysisStatusBadge } from "./AnalysisStatusBadge.jsx";
import { formatDate } from "./formatUtils.js";
import { scoreStateLabel } from "./evasionStatus.js";
import { ScoreTrend } from "./EvasionCharts.jsx";

const SCORE_BADGE_CLASS = {
    pass: "bg-success",
    warn: "bg-warning text-dark",
    fail: "bg-danger",
    incomplete: "bg-secondary",
};

function ScoreCell({ score }) {
    if (!score) {
        return <span className="text-muted">-</span>;
    }
    const badgeClass = SCORE_BADGE_CLASS[score.state] || "bg-secondary";
    return (
        <span>
            <span className={`badge ${badgeClass} me-2`}>
                {typeof score.chimera_score === "number"
                    ? score.chimera_score.toFixed(1)
                    : scoreStateLabel(score.state)}
            </span>
            {typeof score.chimera_score === "number"
                ? scoreStateLabel(score.state)
                : []}
        </span>
    );
}

function durationLabel(run) {
    if (!run.time_started || !run.time_finished) return "-";
    const ms = new Date(run.time_finished) - new Date(run.time_started);
    if (isNaN(ms) || ms < 0) return "-";
    const minutes = Math.floor(ms / 60000);
    const seconds = Math.floor((ms % 60000) / 1000);
    return `${minutes}m ${seconds}s`;
}

function VerificationRunRow({ run }) {
    const sandbox = run.sandbox || {};
    return (
        <tr>
            <td>
                <AnalysisStatusBadge
                    status={run.status}
                    substatus={run.substatus}
                />
                <Link to={`/evasion/${run.id}`}>{run.id}</Link>
            </td>
            <td>
                {sandbox.display_name || sandbox.id}
                {sandbox.platform ? ` (${sandbox.platform})` : ""}
            </td>
            <td>{(run.tools || []).join(", ")}</td>
            <td>{run.profile}</td>
            <td>
                <ScoreCell score={run.score} />
            </td>
            <td>{formatDate(run.time_started)}</td>
            <td>{durationLabel(run)}</td>
        </tr>
    );
}

function VerificationRunsTable({ runs }) {
    return (
        <div className="datatable-container">
            <table className="datatable-table">
                <thead>
                    <tr>
                        <th>Scan</th>
                        <th>Sandbox</th>
                        <th>Tools</th>
                        <th>Profile</th>
                        <th>CHIMERA score</th>
                        <th>Started</th>
                        <th>Duration</th>
                    </tr>
                </thead>
                <tbody>
                    {runs.map((run) => (
                        <VerificationRunRow run={run} key={run.id} />
                    ))}
                </tbody>
            </table>
        </div>
    );
}

function VerificationRunsList() {
    const [error, setError] = useState();
    const [runs, setRuns] = useState();

    useEffect(() => {
        const abortController = new AbortController();
        getScanList({ abortController })
            .then((response) => setRuns(response))
            .catch((error) => {
                if (!(error instanceof CanceledError)) {
                    setError(error);
                    console.error(error);
                }
            });
        return () => {
            abortController.abort();
        };
    }, []);

    if (typeof error !== "undefined") {
        return <div className="text-danger">Error: {error.toString()}</div>;
    }

    if (typeof runs === "undefined") {
        return <div>Loading...</div>;
    }

    if (runs.length === 0) {
        return (
            <div>
                There are no verification runs yet. Start one from Sandbox
                Evasion.
            </div>
        );
    }

    return (
        <>
            <div className="card mb-4">
                <div className="card-body">
                    <h6>CHIMERA score trend</h6>
                    <ScoreTrend runs={runs} />
                </div>
            </div>
            <VerificationRunsTable runs={runs} />
        </>
    );
}

export default function VerificationRuns() {
    return (
        <div className="container-fluid px-4">
            <h1 className="m-4 h4">Verification runs</h1>
            <VerificationRunsList />
        </div>
    );
}
