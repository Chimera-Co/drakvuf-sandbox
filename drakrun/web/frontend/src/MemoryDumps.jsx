import { getMemdumps } from "./api.js";
import { SEVERITY_CLASS, useOptionalJson } from "./AnalysisVerdict.jsx";

const LEVEL_CLASS = {
    high: "text-danger",
    medium: "text-warning-emphasis",
    low: "text-body",
    clean: "text-muted",
};

const size = (bytes) =>
    bytes >= 1 << 20
        ? `${(bytes / (1 << 20)).toFixed(1)} MiB`
        : `${Math.max(1, Math.round(bytes / 1024))} KiB`;

function DumpRow({ dump }) {
    const iocs = Object.values(dump.iocs || {}).flat();
    return (
        <tr>
            <td>
                <div className="fw-semibold text-break" title={dump.process}>
                    {dump.process?.split("\\").pop() || "–"}
                    {dump.sample_tree ? (
                        <span className="badge bg-primary ms-1">sample</span>
                    ) : null}
                </div>
                <div className="small text-muted">
                    PID {dump.pid ?? "–"} · {dump.reason || "–"}
                </div>
                <div className="small text-muted font-monospace text-break">
                    {dump.address || ""}
                </div>
                <div className="small text-muted">
                    {dump.format || "–"}
                    {dump.pe_kind ? ` · ${dump.pe_kind}` : ""} ·{" "}
                    {size(dump.size)}
                </div>
                <div
                    className="small font-monospace text-muted"
                    title={dump.sha256}
                >
                    {dump.sha256?.slice(0, 16)}
                </div>
            </td>
            <td className={LEVEL_CLASS[dump.level] || ""}>
                {dump.error ? (
                    <span className="text-warning-emphasis" title={dump.error}>
                        error
                    </span>
                ) : (
                    <>
                        <div className="fw-semibold">{dump.level || "–"}</div>
                        <div className="small">{dump.score ?? "–"}/100</div>
                    </>
                )}
            </td>
            <td>
                {dump.yara?.map((rule) => (
                    <span key={rule} className="badge bg-danger me-1">
                        {rule}
                    </span>
                ))}
                {dump.findings?.map((f) => (
                    <div key={f.id} className="small">
                        <span
                            className={`badge me-1 ${SEVERITY_CLASS[f.severity] || "bg-secondary"}`}
                        >
                            {f.severity}
                        </span>
                        {f.title}
                    </div>
                ))}
                {dump.embedded_executables ? (
                    <div className="small">
                        {dump.embedded_executables} embedded executable(s)
                    </div>
                ) : null}
                {iocs.length ? (
                    <div className="small font-monospace text-break">
                        {iocs.join(", ")}
                    </div>
                ) : null}
            </td>
        </tr>
    );
}

export default function MemoryDumps({ analysisId }) {
    const state = useOptionalJson(getMemdumps, analysisId);
    if (state.loading) return <div role="status">Loading memory dumps…</div>;
    if (state.missing)
        return (
            <div role="status">
                {state.polling
                    ? "Memory dumps not scanned yet: the scan runs on the deep queue after the analysis (this updates by itself)."
                    : "No memory-dump scan for this analysis (off on this server, or the run took no dumps)."}
            </div>
        );
    if (state.error)
        return <div role="status">Error: {String(state.error)}</div>;
    const doc = state.data;
    const hits = doc.scanned.filter((d) => d.yara?.length).length;
    return (
        <div>
            <p className="small text-muted">
                DRAKVUF dumps memory regions on heuristics (remote threads,
                written-then-executed memory, freed images). Each selected dump
                goes through the static analyzer: YARA, PE parsing, embedded
                executables, strings and IOCs. These results are not classifier
                features.
            </p>
            {doc.error ? (
                <div className="alert alert-warning">{doc.error}</div>
            ) : null}
            <div className="static-metrics mb-3">
                {[
                    ["Dumps in the run", doc.dumps_total],
                    ["Scanned", doc.scanned.length],
                    ["With YARA matches", hits],
                    ["Duplicates", doc.duplicates],
                    ["Not scanned", doc.skipped],
                    ["Scan time", doc.wall_s != null ? `${doc.wall_s} s` : "–"],
                ].map(([label, value]) => (
                    <div className="card" key={label}>
                        <div className="card-body p-3">
                            <div className="small text-muted">{label}</div>
                            <div
                                className={`fw-semibold ${label === "With YARA matches" && value ? "text-danger" : ""}`}
                            >
                                {value}
                            </div>
                        </div>
                    </div>
                ))}
            </div>
            {doc.scanned.length ? (
                <div className="table-responsive">
                    <table
                        aria-label="Scanned memory dumps"
                        className="table table-sm align-top memdump-table"
                    >
                        <colgroup>
                            <col style={{ width: "14rem" }} />
                            <col style={{ width: "6rem" }} />
                            <col />
                        </colgroup>
                        <thead>
                            <tr>
                                <th>Dump</th>
                                <th>Assessment</th>
                                <th>YARA · findings · IOCs</th>
                            </tr>
                        </thead>
                        <tbody>
                            {doc.scanned.map((dump) => (
                                <DumpRow key={dump.member} dump={dump} />
                            ))}
                        </tbody>
                    </table>
                </div>
            ) : (
                <div className="text-muted">No dump was scanned.</div>
            )}
        </div>
    );
}
