import StaticWorkspace from "./static/StaticWorkspace.jsx";
import { useEffect, useState } from "react";
import { getClassification, getDeepStatic } from "./api.js";

const LABEL_CLASS = {
    malicious: "bg-danger",
    suspicious: "bg-warning text-dark",
    benign: "bg-success",
    unknown: "bg-secondary",
};

export const SEVERITY_CLASS = {
    critical: "bg-danger",
    high: "bg-danger",
    medium: "bg-warning text-dark",
    low: "bg-info text-dark",
    info: "bg-secondary",
};

// A 404 means the worker has not finished; retry for up to 15 minutes.
export function useOptionalJson(loader, analysisId) {
    const [state, setState] = useState({ loading: true });
    useEffect(() => {
        let active = true;
        let retryTimer;
        let polling = true;
        setState({ loading: true });
        const deadlineTimer = setTimeout(
            () => {
                polling = false;
                clearTimeout(retryTimer);
                if (active)
                    setState((current) =>
                        current.missing ? { missing: true } : current,
                    );
            },
            15 * 60 * 1000,
        );
        const load = () => {
            loader({ analysisId })
                .then((data) => {
                    if (!active) return;
                    clearTimeout(deadlineTimer);
                    setState({ data });
                })
                .catch((error) => {
                    if (!active) return;
                    if (error?.response?.status === 404) {
                        setState({ missing: true, polling });
                        if (polling) retryTimer = setTimeout(load, 5000);
                    } else {
                        clearTimeout(deadlineTimer);
                        setState({ error });
                    }
                });
        };
        load();
        return () => {
            active = false;
            clearTimeout(retryTimer);
            clearTimeout(deadlineTimer);
        };
    }, [loader, analysisId]);
    return state;
}

function isWarning(line) {
    return (
        /^(No verdict|No static verdict|Static analysis failed)/.test(line) ||
        line.includes("No benign verdict")
    );
}

function Explanation({ lines = [] }) {
    const ordered = [
        ...lines.filter(isWarning),
        ...lines.filter((line) => !isWarning(line)),
    ];
    return (
        <ul className="mb-0 small">
            {ordered.map((line, idx) => (
                <li
                    key={idx}
                    className={
                        isWarning(line)
                            ? "text-warning-emphasis fw-semibold"
                            : undefined
                    }
                >
                    {line}
                </li>
            ))}
        </ul>
    );
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
                    decision score {formatScore(component.score)}
                </span>
                {component.model ? (
                    <span className="text-muted ms-2 small">
                        {component.model} {component.model_version}
                    </span>
                ) : null}
                {component.explanation?.length ? (
                    <Explanation lines={component.explanation} />
                ) : null}
            </td>
        </tr>
    );
}

export function VerdictCard({ analysisId }) {
    const { loading, data, missing, polling, error } = useOptionalJson(
        getClassification,
        analysisId,
    );
    let body;
    if (loading) body = <div>Loading verdict...</div>;
    else if (missing)
        body = (
            <div className="text-muted">
                {polling
                    ? "Not classified yet: waiting for the classifier (this updates by itself)."
                    : "Not classified yet."}
            </div>
        );
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
                    <span>
                        combined decision score {formatScore(data.score)}
                    </span>
                    {data.family ? (
                        <span className="ms-3">family {data.family}</span>
                    ) : null}
                    <span className="text-muted ms-auto small">
                        {data.model} {data.model_version}
                    </span>
                </div>
                <div className="small text-muted mb-2">
                    Decision score: 0.50 is the malicious threshold. It is not a
                    probability.
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
                    <Explanation lines={data.explanation} />
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

function HashValue({ label, value }) {
    const [message, setMessage] = useState("");
    async function copy() {
        try {
            await navigator.clipboard.writeText(value);
            setMessage("Copied");
        } catch {
            setMessage("Copy unavailable; select and copy the hash manually.");
        }
    }
    return (
        <div className="mb-2">
            <strong>{label}: </strong>
            <span className="font-monospace small text-break">
                {value || "not computed"}
            </span>
            {value ? (
                <button
                    type="button"
                    className="btn btn-sm btn-outline-secondary ms-2"
                    aria-label={`Copy ${label}`}
                    onClick={copy}
                >
                    Copy
                </button>
            ) : null}
            <span role="status" className="small ms-2">
                {message}
            </span>
        </div>
    );
}

function DeepStrings({ label, block }) {
    if (!block?.count) return null;
    return (
        <details className="mb-2">
            <summary>
                {label} ({block.count})
            </summary>
            <ul className="small font-monospace text-break mb-0">
                {(block.sample || []).map((value, idx) => (
                    <li key={idx}>{value}</li>
                ))}
            </ul>
        </details>
    );
}

export function DeepSection({ analysisId }) {
    const { loading, data, missing, polling, error } = useOptionalJson(
        getDeepStatic,
        analysisId,
    );
    let body;
    if (loading) body = <div className="text-muted">Loading...</div>;
    else if (missing)
        body = (
            <div className="text-muted">
                {polling
                    ? "Not run yet: capa and FLOSS run after the fast pass (this updates by itself)."
                    : "No deep pass for this analysis (off on this server, or it has not finished)."}
            </div>
        );
    else if (error)
        body = <div className="text-danger">Error: {error.toString()}</div>;
    else if (data.error)
        body = (
            <div className="text-danger">Deep pass failed: {data.error}</div>
        );
    else {
        const capa = data.capa;
        const floss = data.floss;
        const hidden = floss
            ? ["stack", "tight", "decoded"].reduce(
                  (sum, kind) => sum + (floss[kind]?.count || 0),
                  0,
              )
            : 0;
        body = (
            <>
                {capa ? (
                    <>
                        <div className="small text-muted mb-1">
                            capa {capa.version}: {capa.rules_total} capabilities
                            {capa.library_signatures
                                ? ""
                                : " (library code not filtered: no signatures)"}
                        </div>
                        {capa.rules?.length ? (
                            <table className="table table-sm">
                                <thead>
                                    <tr>
                                        <th>Capability</th>
                                        <th>Namespace</th>
                                        <th>ATT&amp;CK</th>
                                        <th>MBC</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {capa.rules.map((rule) => (
                                        <tr key={rule.name}>
                                            <td>{rule.name}</td>
                                            <td className="small text-muted">
                                                {rule.namespace}
                                            </td>
                                            <td className="small">
                                                {(rule.attack || [])
                                                    .map(
                                                        (entry) =>
                                                            entry.id || entry,
                                                    )
                                                    .join(", ")}
                                            </td>
                                            <td className="small">
                                                {(rule.mbc || [])
                                                    .map(
                                                        (entry) =>
                                                            entry.id || entry,
                                                    )
                                                    .join(", ")}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        ) : (
                            <div className="text-muted mb-2">
                                No capabilities matched.
                            </div>
                        )}
                    </>
                ) : null}
                {floss ? (
                    <>
                        <div className="small text-muted mb-1">
                            FLOSS {floss.version}: {hidden} hidden strings
                        </div>
                        <DeepStrings
                            label="Stack strings"
                            block={floss.stack}
                        />
                        <DeepStrings
                            label="Tight strings"
                            block={floss.tight}
                        />
                        <DeepStrings
                            label="Decoded strings"
                            block={floss.decoded}
                        />
                    </>
                ) : null}
                {data.errors?.length ? (
                    <ul className="small text-warning-emphasis">
                        {data.errors.map((entry, idx) => (
                            <li key={idx}>
                                {entry.stage}: {entry.error}
                            </li>
                        ))}
                    </ul>
                ) : null}
            </>
        );
    }
    return (
        <section aria-label="Capabilities" className="mb-3">
            <h6>Capabilities and hidden strings (capa, FLOSS)</h6>
            {body}
        </section>
    );
}

export function StaticAnalysisTab({ analysisId }) {
    return <StaticWorkspace analysisId={analysisId} />;
}

export function StaticOverview({ data }) {
    const type = data.type || {};
    const file = data.file || {};
    const findings = data.findings || [];
    const coverage = data.coverage;
    const failed = coverage?.failed_stages || [];
    const reasons = [
        coverage?.type_plugin === null
            ? `no parser for ${type.format} files`
            : null,
        failed.length ? `failed: ${failed.join(", ")}` : null,
    ].filter(Boolean);
    const ruleset = data.universal?.yara_ruleset;
    const yara =
        ruleset?.rules != null
            ? `${ruleset.rules} rules${ruleset.sources?.length ? ` (${ruleset.sources.map((source) => `${source.name} @ ${source.commit?.slice(0, 7) || "unknown"}`).join(", ")})` : ""}`
            : ruleset?.note || "no rules";
    return (
        <div className="py-2 text-break">
            <div className="static-metrics mb-3">
                <section aria-label="Format" className="card">
                    <div className="card-body p-3">
                        <h6 className="mt-0">Format</h6>
                        <div className="fw-semibold text-break">
                            {[type.format, type.platform, type.arch]
                                .filter(Boolean)
                                .join(" / ")}
                        </div>
                        <div className="small text-muted text-break">
                            {type.magic}
                        </div>
                    </div>
                </section>
                <section aria-label="Coverage" className="card">
                    <div className="card-body p-3">
                        <h6 className="mt-0">Coverage</h6>
                        <div
                            className={
                                coverage?.complete
                                    ? "text-success"
                                    : "text-warning-emphasis"
                            }
                        >
                            {!coverage
                                ? "not reported (older analyzer)"
                                : coverage.complete
                                  ? "complete"
                                  : `partial${reasons.length ? `: ${reasons.join("; ")}` : ""}`}
                        </div>
                    </div>
                </section>
                <section aria-label="YARA ruleset" className="card">
                    <div className="card-body p-3">
                        <h6 className="mt-0">YARA</h6>
                        <div className="small text-break">
                            {yara}
                            {failed.includes("yara")
                                ? " - scan did not run"
                                : ""}
                        </div>
                    </div>
                </section>
            </div>
            <p className="small text-muted text-break">
                Analyzer {data.analyzer_version || "unknown"} ·{" "}
                {data.container?.engine || "engine not reported"} ·{" "}
                {data.duration_s ?? "–"}s
            </p>
            <section aria-label="Hashes" className="mb-3">
                <h6>Hashes</h6>
                {file.md5 && <HashValue label="MD5" value={file.md5} />}
                {file.sha1 && <HashValue label="SHA-1" value={file.sha1} />}
                <HashValue label="SHA-256" value={file.sha256} />
                <HashValue label="ssdeep" value={file.ssdeep} />
                <HashValue label="TLSH" value={file.tlsh} />
                <HashValue label="imphash" value={data.pe?.imphash} />
            </section>
            <section aria-label="Findings">
                <h6>Findings ({findings.length})</h6>
                {findings.length ? (
                    <div className="table-responsive">
                        <table
                            aria-label="Findings"
                            className="table table-sm static-table"
                        >
                            <thead>
                                <tr>
                                    <th scope="col">Severity</th>
                                    <th scope="col">Finding</th>
                                    <th scope="col">Evidence</th>
                                    <th scope="col">ATT&amp;CK</th>
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
                                        <td className="text-break">
                                            {finding.title}
                                        </td>
                                        <td className="small text-break">
                                            {finding.evidence}
                                        </td>
                                        <td className="small">
                                            {(finding.attack || []).map(
                                                (entry, i) => (
                                                    <span
                                                        key={i}
                                                        className="badge bg-secondary me-1 text-wrap"
                                                    >
                                                        {entry.id || entry}
                                                    </span>
                                                ),
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                ) : (
                    <div className="text-muted">No findings.</div>
                )}
            </section>
            {data.errors?.length ? (
                <>
                    <h6>Analyzer errors</h6>
                    <ul className="small text-break">
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
