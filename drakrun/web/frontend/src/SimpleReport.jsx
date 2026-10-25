import { useMemo, useState } from "react";
import axios from "axios";
import { AttackMatrix } from "./AttackMatrix.jsx";
import { useAttackEntries } from "./AnalysisDashboard.jsx";
import { SectionOutline } from "./EdgeDrawer.jsx";

const count = (value) =>
    Array.isArray(value)
        ? value.length
        : value && typeof value === "object"
          ? Object.keys(value).length
          : 0;

const IOC_LABEL = {
    domain: "Domains",
    ipv4: "IP addresses",
    ip: "IP addresses",
    url: "URLs",
    sha256: "Hashes",
    email: "E-mail addresses",
    file: "Files",
    registry: "Registry keys",
    mutex: "Mutexes",
};
const IOCS_PER_GROUP = 8;
const CLAIMS_SHOWN = 12;

function Section({ id, title, count: n, children }) {
    return (
        <section id={id} data-outline={title} className="report-section">
            <h2>
                {title}
                {n != null ? (
                    <span className="badge bg-secondary">{n}</span>
                ) : null}
            </h2>
            {children}
        </section>
    );
}

function Claims({ claims, processes, onSelect }) {
    const [all, setAll] = useState(false);
    const ordered = [
        ...claims.filter((c) => c.kind === "observed"),
        ...claims.filter((c) => c.kind !== "observed"),
    ];
    const shown = all ? ordered : ordered.slice(0, CLAIMS_SHOWN);
    return (
        <>
            <ul className="claim-list">
                {shown.map((claim) => {
                    const process =
                        claim.process_seqid != null
                            ? processes?.[claim.process_seqid]
                            : null;
                    return (
                        <li key={claim.id}>
                            <span
                                className={`claim-kind is-${claim.kind === "observed" ? "observed" : "inferred"}`}
                                title={claim.rationale || undefined}
                            >
                                {claim.kind === "observed"
                                    ? "Observed"
                                    : "Inferred"}
                            </span>
                            <span className="flex-grow-1">
                                {claim.text}
                                {claim.confidence &&
                                claim.confidence !== "unknown" ? (
                                    <span className="text-muted small ms-2">
                                        {claim.confidence} confidence
                                    </span>
                                ) : null}
                            </span>
                            {process && onSelect ? (
                                <button
                                    type="button"
                                    className="btn btn-sm btn-outline-secondary text-nowrap"
                                    onClick={() =>
                                        onSelect(claim.process_seqid)
                                    }
                                >
                                    {(process.procname || process.name || "")
                                        .split(/[\\/]/)
                                        .pop()}{" "}
                                    ({process.pid})
                                </button>
                            ) : null}
                        </li>
                    );
                })}
            </ul>
            {ordered.length > CLAIMS_SHOWN ? (
                <button
                    type="button"
                    className="btn btn-sm btn-link px-0 mt-1"
                    onClick={() => setAll(!all)}
                >
                    {all ? "Show fewer" : `Show all ${ordered.length} findings`}
                </button>
            ) : null}
        </>
    );
}

function Iocs({ iocs, analysisId }) {
    const groups = useMemo(() => {
        const out = new Map();
        for (const ioc of iocs) {
            const label = IOC_LABEL[ioc.type] || ioc.type || "Other";
            if (!out.has(label)) out.set(label, []);
            out.get(label).push(ioc);
        }
        return [...out.entries()];
    }, [iocs]);
    const base = axios.defaults.baseURL;
    return (
        <>
            <div className="ioc-groups">
                {groups.map(([label, items]) => (
                    <div className="ioc-group" key={label}>
                        <h3>
                            {label}
                            <span className="badge bg-secondary">
                                {items.length}
                            </span>
                        </h3>
                        <ul>
                            {items.slice(0, IOCS_PER_GROUP).map((ioc) => (
                                <li
                                    key={`${ioc.type}/${ioc.value}`}
                                    title={ioc.source || undefined}
                                >
                                    {ioc.value}
                                    {/not observed/i.test(ioc.source || "") ? (
                                        <span className="text-muted ms-1">
                                            (string in file)
                                        </span>
                                    ) : null}
                                </li>
                            ))}
                        </ul>
                        {items.length > IOCS_PER_GROUP ? (
                            <div className="small text-muted mt-1">
                                {items.length - IOCS_PER_GROUP} more in the IOC
                                export
                            </div>
                        ) : null}
                    </div>
                ))}
            </div>
            <div className="small mt-2">
                Export all:{" "}
                <a href={`${base}/chimera_report/${analysisId}/iocs.csv`}>
                    CSV
                </a>{" "}
                ·{" "}
                <a href={`${base}/chimera_report/${analysisId}/iocs.json`}>
                    JSON
                </a>
            </div>
        </>
    );
}

// The digest of an analysis: key numbers, what the sample did, ATT&CK, indicators and the limits of the run. The
// advanced view keeps every table and log.
export function SimpleReport({
    analysisId,
    summary,
    chimeraReport,
    reportState,
    onSelect,
    onAdvanced,
}) {
    const attack = useAttackEntries(summary, chimeraReport);
    const report = chimeraReport || {};
    const claims = Array.isArray(report.claims) ? report.claims : [];
    const iocs = Array.isArray(report.iocs) ? report.iocs : [];
    const limitations = Array.isArray(report.limitations)
        ? report.limitations
        : [];
    const techniques = new Set(
        attack.sample.map((e) => e.technique?.split(".")[0]).filter(Boolean),
    ).size;
    const inTree = report.stages?.dynamic?.payload?.processes_in_tree;
    const stats = [
        ["Processes (sample tree)", inTree ?? count(summary?.processes)],
        ["Files written", count(summary?.modified_files)],
        ["Files deleted", count(summary?.deleted_files)],
        ["DNS queries", count(summary?.dns_queries)],
        ["Connections", count(summary?.connections)],
        ["HTTP requests", count(summary?.http_requests)],
        ["ATT&CK techniques", techniques],
        ["Indicators", iocs.length],
    ];
    const outline = useMemo(
        () =>
            [
                { id: "simple-facts", label: "Key facts" },
                chimeraReport
                    ? {
                          id: "simple-findings",
                          label: "What it did",
                          count: claims.length,
                      }
                    : null,
                {
                    id: "simple-attack",
                    label: "MITRE ATT&CK",
                    count: techniques,
                },
                chimeraReport
                    ? {
                          id: "simple-iocs",
                          label: "Indicators",
                          count: iocs.length,
                      }
                    : null,
                limitations.length
                    ? { id: "simple-limits", label: "Limits of this run" }
                    : null,
            ].filter(Boolean),
        // eslint-disable-next-line react-hooks/exhaustive-deps
        [chimeraReport, techniques],
    );
    return (
        <div className="simple-report">
            <SectionOutline items={outline} title="Report outline" />
            {!chimeraReport ? (
                <div className="alert alert-secondary small py-2">
                    {reportState === "missing"
                        ? "The analyst report is not ready yet (it is written after postprocessing); the numbers below come from the run summary."
                        : reportState === "error"
                          ? "The analyst report could not be loaded; the numbers below come from the run summary."
                          : "Loading the analyst report..."}
                </div>
            ) : null}
            <Section id="simple-facts" title="Key facts">
                {report.assessment?.text ? (
                    <p className="mb-2">{report.assessment.text}</p>
                ) : null}
                <div className="simple-stats">
                    {stats.map(([label, value]) => (
                        <div className="simple-stat" key={label}>
                            <strong>{value ?? "–"}</strong>
                            <span>{label}</span>
                        </div>
                    ))}
                </div>
            </Section>
            {chimeraReport ? (
                <Section
                    id="simple-findings"
                    title="What it did"
                    count={claims.length}
                >
                    {claims.length ? (
                        <Claims
                            claims={claims}
                            processes={summary?.processes}
                            onSelect={onSelect}
                        />
                    ) : (
                        <p className="report-empty-list">
                            No finding was recorded for the sample.
                        </p>
                    )}
                </Section>
            ) : null}
            <Section id="simple-attack" title="MITRE ATT&CK" count={techniques}>
                <AttackMatrix
                    compact
                    entries={attack.sample}
                    systemEntries={attack.system}
                />
            </Section>
            {chimeraReport ? (
                <Section
                    id="simple-iocs"
                    title="Indicators"
                    count={iocs.length}
                >
                    {iocs.length ? (
                        <Iocs iocs={iocs} analysisId={analysisId} />
                    ) : (
                        <p className="report-empty-list">
                            No indicator was extracted.
                        </p>
                    )}
                </Section>
            ) : null}
            {limitations.length ? (
                <Section id="simple-limits" title="Limits of this run">
                    <ul className="small mb-0">
                        {limitations.map((line) => (
                            <li key={line}>{line}</li>
                        ))}
                    </ul>
                </Section>
            ) : null}
            <p className="small text-muted">
                Every table, log, the static analysis and the memory dumps are
                in the{" "}
                <button
                    type="button"
                    className="btn btn-link btn-sm p-0 align-baseline"
                    onClick={onAdvanced}
                >
                    advanced view
                </button>
                .
            </p>
        </div>
    );
}
