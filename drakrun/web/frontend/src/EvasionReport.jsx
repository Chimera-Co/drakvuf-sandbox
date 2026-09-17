import axios, { CanceledError } from "axios";
import { useEffect, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faDownload } from "@fortawesome/free-solid-svg-icons";
import { Tab, TabSwitcher } from "./TabSwitcher.jsx";
import { ScoreGauge, CategoryRadar } from "./EvasionCharts.jsx";
import { EvasionCheckTable } from "./EvasionCheckTable.jsx";
import { scoreStateLabel } from "./evasionStatus.js";
import { getScanFileList } from "./evasionApi.js";
import { formatDate } from "./formatUtils.js";

const SCORE_BADGE_CLASS = {
    pass: "bg-success",
    warn: "bg-warning text-dark",
    fail: "bg-danger",
    incomplete: "bg-secondary",
};

function ScoreBadge({ state }) {
    return (
        <span
            className={`badge ${SCORE_BADGE_CLASS[state] || "bg-secondary"} p-2`}
        >
            {scoreStateLabel(state)}
        </span>
    );
}

/**
 * The one place tool-native results and the CHIMERA score are shown
 * together - and where the distinction the task calls out explicitly is
 * made visually unmistakable: only score.primary_tool's row is tagged as
 * the CHIMERA score's source, and every other tool's "native weighted
 * score" cell is replaced with an explicit "not scored" caption instead of
 * a number, dash, or anything that could be misread as contributing.
 */
function ToolNativeTable({ toolScores, primaryTool }) {
    const entries = Object.entries(toolScores || {});
    if (entries.length === 0) {
        return (
            <div className="text-muted small">
                No tool results are available for this scan.
            </div>
        );
    }
    return (
        <div className="datatable-container">
            <table className="datatable-table">
                <thead>
                    <tr>
                        <th>Tool</th>
                        <th>Run status</th>
                        <th>Clean / Applicable</th>
                        <th>Detected</th>
                        <th>Errored</th>
                        <th>Skipped</th>
                        <th>Native weighted score</th>
                    </tr>
                </thead>
                <tbody>
                    {entries.map(([toolId, summary]) => (
                        <tr key={toolId}>
                            <td>
                                {toolId}
                                {toolId === primaryTool ? (
                                    <span className="badge bg-primary ms-2">
                                        CHIMERA score source
                                    </span>
                                ) : (
                                    []
                                )}
                            </td>
                            <td>{summary.status}</td>
                            <td>{summary.raw_score}</td>
                            <td>{summary.detected ?? 0}</td>
                            <td>{summary.errored ?? 0}</td>
                            <td>{summary.skipped ?? 0}</td>
                            <td>
                                {typeof summary.weighted_score === "number" ? (
                                    summary.weighted_score.toFixed(2)
                                ) : (
                                    <span className="text-muted fst-italic">
                                        {toolId === primaryTool
                                            ? "n/a"
                                            : "not scored (corroborating evidence only)"}
                                    </span>
                                )}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

function ScoreSection({ score }) {
    if (!score) {
        return (
            <div className="text-muted">
                No score information is available for this scan.
            </div>
        );
    }
    return (
        <div className="row">
            <div className="col-md-4">
                <ScoreGauge score={score.chimera_score} state={score.state} />
                <div className="text-center">
                    <ScoreBadge state={score.state} />
                </div>
            </div>
            <div className="col-md-8">
                <h6>Why this score?</h6>
                <ul className="small">
                    {(score.rationale || []).map((line, idx) => (
                        <li key={idx}>{line}</li>
                    ))}
                </ul>
            </div>
            <div className="col-12 mt-3">
                <h6>Category breakdown (CHIMERA score only)</h6>
                <CategoryRadar perCategory={score.per_category} />
            </div>
            <div className="col-12 mt-3">
                <h6>Tool-native results</h6>
                <p className="small text-muted">
                    Only {score.primary_tool || "the primary tool"}&apos;s own
                    severity-weighted score feeds the CHIMERA score above. Every
                    other tool&apos;s results are corroborating evidence only
                    and never change that number.
                </p>
                <ToolNativeTable
                    toolScores={score.tool_scores}
                    primaryTool={score.primary_tool}
                />
            </div>
        </div>
    );
}

function EvasionFiles({ scanId }) {
    const [files, setFiles] = useState();
    const [error, setError] = useState();
    const baseUrl = axios.defaults.baseURL;

    useEffect(() => {
        const abortController = new AbortController();
        getScanFileList({ scanId, abortController })
            .then((response) => setFiles(response.slice().sort()))
            .catch((err) => {
                if (!(err instanceof CanceledError)) {
                    setError(err);
                    console.error(err);
                }
            });
        return () => {
            abortController.abort();
        };
    }, [scanId]);

    if (typeof error !== "undefined") {
        return <div className="text-danger">Error: {error.toString()}</div>;
    }
    if (typeof files === "undefined") {
        return <div>Loading files...</div>;
    }

    return (
        <div>
            <a href={`${baseUrl}/evasion/scans/${scanId}/logs`}>
                <button className="btn btn-primary mb-3">
                    <FontAwesomeIcon icon={faDownload} className="me-2" />
                    Download all raw artifacts (.zip)
                </button>
            </a>
            {files.length === 0 ? (
                <div className="text-muted small">
                    No raw artifacts are available for this scan yet.
                </div>
            ) : (
                <ul className="list-unstyled">
                    {files.map((file) => (
                        <li key={file} className="font-monospace small">
                            <a
                                href={`${baseUrl}/evasion/scans/${scanId}/files/download?filename=${encodeURIComponent(file)}`}
                            >
                                {file}
                            </a>
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
}

export function EvasionReport({ scan }) {
    const baseUrl = axios.defaults.baseURL;
    const [activeTab, setActiveTab] = useState("Overview");
    const sandbox = scan.sandbox || {};
    const options = scan.options || {};

    return (
        <>
            <div className="row mb-4">
                <div className="col">
                    <div className="card">
                        <div className="card-body">
                            <div className="d-flex flex-wrap justify-content-between">
                                <div>
                                    <div className="fw-bold">
                                        {sandbox.display_name || sandbox.id}
                                    </div>
                                    <div className="text-muted small">
                                        Platform: {sandbox.platform} &middot;
                                        Profile: {options.profile} &middot;
                                        Tools:{" "}
                                        {(options.tools || []).join(", ")}
                                    </div>
                                    <div className="text-muted small">
                                        Started: {formatDate(scan.time_started)}{" "}
                                        &middot; Finished:{" "}
                                        {formatDate(scan.time_finished)}
                                    </div>
                                </div>
                                <div>
                                    <a
                                        href={`${baseUrl}/evasion/scans/${scan.id}/json`}
                                    >
                                        <button className="btn btn-outline-primary btn-sm m-1">
                                            <FontAwesomeIcon
                                                icon={faDownload}
                                                className="me-2"
                                            />
                                            Normalized JSON
                                        </button>
                                    </a>
                                    <a
                                        href={`${baseUrl}/evasion/scans/${scan.id}/report`}
                                    >
                                        <button className="btn btn-outline-primary btn-sm m-1">
                                            <FontAwesomeIcon
                                                icon={faDownload}
                                                className="me-2"
                                            />
                                            HTML report
                                        </button>
                                    </a>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div className="card">
                <div className="card-body">
                    <TabSwitcher
                        activeTab={activeTab}
                        onTabSwitch={setActiveTab}
                    >
                        <Tab tab="Overview">
                            <div className="pt-3">
                                <ScoreSection score={scan.score} />
                            </div>
                        </Tab>
                        <Tab tab="Checks">
                            <div className="pt-3">
                                <EvasionCheckTable
                                    toolResults={scan.tool_results}
                                />
                            </div>
                        </Tab>
                        <Tab tab="Files">
                            <div className="pt-3">
                                <EvasionFiles scanId={scan.id} />
                            </div>
                        </Tab>
                    </TabSwitcher>
                </div>
            </div>
        </>
    );
}
