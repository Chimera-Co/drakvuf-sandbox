import { Link, useSearchParams } from "react-router-dom";
import { useEffect, useState } from "react";
import { getAnalysisList } from "./api";
import { CanceledError } from "axios";
import { AnalysisStatusBadge } from "./AnalysisStatusBadge.jsx";
import { formatDate, formatSandbox } from "./formatUtils.js";

function AnalysisListRow({ analysis }) {
    return (
        <tr>
            <td>
                <AnalysisStatusBadge status={analysis.status} />
                <Link to={`/analysis/${analysis.id}`}>{analysis.id}</Link>
            </td>
            <td>
                <div className="d-flex flex-row flex-wrap font-monospace">
                    <div className="fw-bold pe-2">SHA256:</div>
                    <div>{analysis.file?.sha256}</div>
                </div>
                <div className="d-flex flex-row flex-wrap font-monospace">
                    <div className="fw-bold pe-2">Name:</div>
                    <div>{analysis.file?.name}</div>
                </div>
                <div className="d-flex flex-row flex-wrap">
                    <div className="fw-bold pe-2">Type:</div>
                    <div>{analysis.file?.type}</div>
                </div>
            </td>
            <td>{formatSandbox(analysis)}</td>
            <td>{formatDate(analysis.time_started)}</td>
            <td>{formatDate(analysis.time_finished)}</td>
        </tr>
    );
}

function AnalysisListTable() {
    const [params, setParams] = useSearchParams();
    function updateFilter(key, value) {
        const next = new URLSearchParams(params);
        if (value) next.set(key, value);
        else next.delete(key);
        setParams(next, { replace: true });
    }
    const [error, setError] = useState();
    const [analysisList, setAnalysisList] = useState();

    useEffect(() => {
        const abortController = new AbortController();
        getAnalysisList({ abortController })
            .then((response) => {
                setAnalysisList(response);
            })
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
        return <div>Error: {error.toString()}</div>;
    }

    if (typeof analysisList === "undefined") {
        return <div>Loading...</div>;
    }

    if (analysisList.length === 0) {
        return (
            <div>There are no analyses. Upload sample to create a new one.</div>
        );
    }

    const filtered = analysisList.filter((analysis) => {
        const verdict = analysis.classification
            ? ["malicious", "suspicious", "benign"].includes(
                  analysis.classification.label,
              )
                ? analysis.classification.label
                : "no verdict"
            : "not classified";
        const query = (params.get("q") || "").trim().toLowerCase();
        return (
            (!params.get("os") ||
                params.get("os") ===
                    (analysis.options?.guest_os || "windows")) &&
            (!params.get("status") ||
                params.get("status") === analysis.status) &&
            (!params.get("verdict") || params.get("verdict") === verdict) &&
            ["name", "md5", "sha1", "sha256"].some((key) =>
                (analysis.file?.[key] || "").toLowerCase().includes(query),
            )
        );
    });
    return (
        <div className="datatable-container">
            <div className="d-flex flex-wrap gap-2 mb-3">
                {Object.entries({
                    os: ["windows", "linux"],
                    status: [
                        "created",
                        "queued",
                        "started",
                        "finished",
                        "failed",
                        "deferred",
                        "scheduled",
                        "stopped",
                        "canceled",
                        "unknown",
                    ],
                    verdict: [
                        "malicious",
                        "suspicious",
                        "benign",
                        "no verdict",
                        "not classified",
                    ],
                }).map(([key, values]) => (
                    <label key={key}>
                        {key === "os"
                            ? "OS"
                            : key === "status"
                              ? "Status"
                              : "Verdict"}
                        <select
                            className="form-select"
                            value={params.get(key) || ""}
                            onChange={(event) =>
                                updateFilter(key, event.target.value)
                            }
                        >
                            <option value="">All</option>
                            {values.map((value) => (
                                <option key={value} value={value}>
                                    {value}
                                </option>
                            ))}
                        </select>
                    </label>
                ))}
                <label>
                    Search name or hash
                    <input
                        className="form-control"
                        type="search"
                        value={params.get("q") || ""}
                        onChange={(event) =>
                            updateFilter("q", event.target.value)
                        }
                    />
                </label>
            </div>
            {filtered.length === 0 ? (
                <div>No analyses match these filters.</div>
            ) : null}
            <table className="datatable-table">
                <thead>
                    <tr>
                        <th>Analysis ID</th>
                        <th>Sample info</th>
                        <th>Sandbox</th>
                        <th>Started</th>
                        <th>Finished</th>
                    </tr>
                </thead>
                <tbody>
                    {filtered.map((analysis) => (
                        <AnalysisListRow
                            analysis={analysis}
                            key={analysis.id}
                        />
                    ))}
                </tbody>
            </table>
        </div>
    );
}

export default function AnalysisList() {
    return (
        <div className="container-fluid px-4">
            <h1 className="m-4 h4">Analyses</h1>
            <AnalysisListTable />
        </div>
    );
}
