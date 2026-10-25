import { useEffect, useState } from "react";
import { getClassification, getDeepStatic, getStaticReport } from "./api.js";

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

// A 404 means the worker has not finished; retry for up to 15 minutes.
function useOptionalJson(loader, analysisId) {
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
                                                {(rule.attack || []).join(", ")}
                                            </td>
                                            <td className="small">
                                                {(rule.mbc || []).join(", ")}
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
    const { loading, data, missing, polling, error } = useOptionalJson(
        getStaticReport,
        analysisId,
    );
    if (loading) return <div className="py-2">Loading static analysis...</div>;
    if (missing)
        return (
            <div className="py-2 text-muted">
                {polling
                    ? "No static analysis yet: waiting for static analysis (this updates by itself)."
                    : "No static analysis for this analysis (static analysis was off, or it has not finished)."}
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
                        <th>Coverage</th>
                        <td>
                            {!coverage
                                ? "not reported (older analyzer)"
                                : coverage.complete
                                  ? "complete"
                                  : `partial${reasons.length ? `: ${reasons.join("; ")}` : ""}`}
                        </td>
                    </tr>
                    <tr>
                        <th>YARA</th>
                        <td>
                            {yara}
                            {failed.includes("yara")
                                ? " - scan did not run"
                                : ""}
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
            <section aria-label="Hashes" className="mb-3">
                <h6>Hashes</h6>
                <HashValue label="SHA-256" value={file.sha256} />
                <HashValue label="ssdeep" value={file.ssdeep} />
                <HashValue label="TLSH" value={file.tlsh} />
                <HashValue label="imphash" value={data.pe?.imphash} />
            </section>
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
            {["pe", "elf"].includes(type.format) ? (
                <DeepSection analysisId={analysisId} />
            ) : null}
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
