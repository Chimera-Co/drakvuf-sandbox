import { useEffect, useState } from "react";
import { getClassification, getStaticReport } from "./api.js";

const LABEL_CLASS = {
    malicious: "bg-danger",
    suspicious: "bg-warning text-dark",
    benign: "bg-success",
    unknown: "bg-secondary",
};

const SEVERITY_CLASS = {
    critical: "bg-danger",
    high: "bg-danger",
    medium: "bg-warning text-dark",
    low: "bg-info text-dark",
    info: "bg-secondary",
};

// Fetches once; a 404 means "not there yet" (the static worker or the classifier has not finished)
function useOptionalJson(loader, analysisId) {
    const [state, setState] = useState({ loading: true });
    useEffect(() => {
        let active = true;
        setState({ loading: true });
        loader({ analysisId })
            .then((data) => active && setState({ data }))
            .catch((error) => {
                if (!active) return;
                if (error?.response?.status === 404)
                    setState({ missing: true });
                else setState({ error });
            });
        return () => {
            active = false;
        };
    }, [loader, analysisId]);
    return state;
}

// "unknown" means the model abstained (too little behaviour, unsupported OS, model error)
export function LabelBadge({ label }) {
    return (
        <span className={`badge ${LABEL_CLASS[label] || "bg-secondary"}`}>
            {!label || label === "unknown" ? "no verdict" : label}
        </span>
    );
}

function formatScore(score) {
    return typeof score === "number" ? score.toFixed(2) : "–";
}

function ComponentRow({ name, component }) {
    return (
        <tr>
            <th className="text-capitalize">{name}</th>
            <td>
                <LabelBadge label={component.label} />{" "}
                <span className="ms-1">
                    score {formatScore(component.score)}
                </span>
                {component.model ? (
                    <span className="text-muted ms-2 small">
                        {component.model} {component.model_version}
                    </span>
                ) : null}
                {component.explanation?.length ? (
                    <ul className="mb-0 small">
                        {component.explanation.map((line, idx) => (
                            <li key={idx}>{line}</li>
                        ))}
                    </ul>
                ) : null}
            </td>
        </tr>
    );
}

export function VerdictCard({ analysisId }) {
    const { loading, data, missing, error } = useOptionalJson(
        getClassification,
        analysisId,
    );
    let body;
    if (loading) body = <div>Loading verdict...</div>;
    else if (missing)
        body = <div className="text-muted">Not classified yet.</div>;
    else if (error)
        body = <div className="text-danger">Error: {error.toString()}</div>;
    else if (data.error)
        body = (
            <div>
                <LabelBadge label="unknown" />
                <span className="ms-2 text-danger">{data.error}</span>
            </div>
        );
    else {
        const components = Object.entries(data.components || {});
        body = (
            <>
                <div className="d-flex align-items-center mb-2">
                    <span className="fs-5 me-2">
                        <LabelBadge label={data.label} />
                    </span>
                    <span>combined score {formatScore(data.score)}</span>
                    {data.family ? (
                        <span className="ms-3">family {data.family}</span>
                    ) : null}
                    <span className="text-muted ms-auto small">
                        {data.model} {data.model_version}
                    </span>
                </div>
                {components.length ? (
                    <table className="datatable-table">
                        <tbody>
                            {components.map(([name, component]) => (
                                <ComponentRow
                                    key={name}
                                    name={name}
                                    component={component}
                                />
                            ))}
                        </tbody>
                    </table>
                ) : (
                    <ul className="mb-0 small">
                        {(data.explanation || []).map((line, idx) => (
                            <li key={idx}>{line}</li>
                        ))}
                    </ul>
                )}
            </>
        );
    }
    return (
        <div className="card mb-2">
            <div className="card-body">
                <h5 className="card-title h6">Classifier verdict</h5>
                {body}
            </div>
        </div>
    );
}

export function StaticAnalysisTab({ analysisId }) {
    const { loading, data, missing, error } = useOptionalJson(
        getStaticReport,
        analysisId,
    );
    if (loading) return <div className="py-2">Loading static analysis...</div>;
    if (missing)
        return (
            <div className="py-2 text-muted">
                No static analysis for this analysis (static analysis was off,
                or it has not finished).
            </div>
        );
    if (error)
        return (
            <div className="py-2 text-danger">Error: {error.toString()}</div>
        );
    if (data.error)
        return (
            <div className="py-2 text-danger">
                Static analysis failed: {data.error}
            </div>
        );
    const type = data.type || {};
    const file = data.file || {};
    const findings = data.findings || [];
    return (
        <div className="py-2">
            <table className="datatable-table mb-3">
                <tbody>
                    <tr>
                        <th>Level</th>
                        <td>
                            {data.level} (score {data.score})
                        </td>
                    </tr>
                    <tr>
                        <th>Format</th>
                        <td>
                            {[type.format, type.platform, type.arch]
                                .filter(Boolean)
                                .join(" / ")}
                            {type.magic ? (
                                <div className="small text-muted">
                                    {type.magic}
                                </div>
                            ) : null}
                        </td>
                    </tr>
                    <tr>
                        <th>Size</th>
                        <td>{file.size} bytes</td>
                    </tr>
                    <tr>
                        <th>MD5 / SHA1</th>
                        <td className="small">
                            {file.md5}
                            <br />
                            {file.sha1}
                        </td>
                    </tr>
                    <tr>
                        <th>Analyzer</th>
                        <td className="small">
                            {data.analyzer_version} in {data.container?.engine}{" "}
                            ({data.duration_s}s)
                        </td>
                    </tr>
                </tbody>
            </table>
            <h6>Findings ({findings.length})</h6>
            {findings.length ? (
                <table className="table table-sm">
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Finding</th>
                            <th>Evidence</th>
                            <th>ATT&amp;CK</th>
                        </tr>
                    </thead>
                    <tbody>
                        {findings.map((finding, idx) => (
                            <tr key={`${finding.id}-${idx}`}>
                                <td>
                                    <span
                                        className={`badge ${SEVERITY_CLASS[finding.severity] || "bg-secondary"}`}
                                    >
                                        {finding.severity}
                                    </span>
                                </td>
                                <td>{finding.title}</td>
                                <td className="small text-break">
                                    {finding.evidence}
                                </td>
                                <td className="small">
                                    {(finding.attack || []).join(", ")}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            ) : (
                <div className="text-muted">No findings.</div>
            )}
            {data.errors?.length ? (
                <>
                    <h6>Analyzer errors</h6>
                    <ul className="small">
                        {data.errors.map((entry, idx) => (
                            <li key={idx}>
                                {entry.stage}: {entry.error}
                            </li>
                        ))}
                    </ul>
                </>
            ) : null}
        </div>
    );
}
