import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import {
    Timeline,
    CountChart,
    LogWorkspace,
    displayValue,
} from "./StructuredLogs.jsx";
import { GenericBlock } from "./static/CodeExplorer.jsx";
import { PAGE_SIZES, Pagination, useLocalPagination } from "./Pagination.jsx";
import { SectionOutline } from "./EdgeDrawer.jsx";
import { AttackMatrix, entriesFromTtps, sampleScope } from "./AttackMatrix.jsx";

const list = (value) =>
    Array.isArray(value)
        ? value
        : value && typeof value === "object"
          ? Object.entries(value).map(([key, item]) =>
                typeof item === "object" && item !== null
                    ? { name: key, ...item }
                    : { name: key, value: item },
            )
          : [];
const PROCESS_KEY =
    /^(process|processes|process_seqid|process_seqids|processSeqid|target_process)$/;
// A column whose values run longer than this wraps; shorter ones stay on one line.
const LONG_VALUE = 48;
// Process columns wrap their chips; past this many the rest is a count (the process tree has them all).
const PROCESS_CHIPS = 12;

export function ReportTable({ label, rows, processes = {}, onSelect, id }) {
    const [query, setQuery] = useState(""),
        [sort, setSort] = useState({ key: "", direction: 1 });
    const data = list(rows).map((value) =>
        typeof value === "object" && value !== null ? value : { value },
    );
    const keys = [...new Set(data.slice(0, 100).flatMap(Object.keys))];
    const columns = [
        ...keys.filter((key) => /process/.test(key)),
        ...keys.filter((key) => !/process/.test(key)),
    ].slice(0, 12);
    const sample = data.slice(0, 200);
    const long = new Set(
        columns.filter(
            (key) =>
                !PROCESS_KEY.test(key) &&
                sample.some(
                    (row) => displayValue(row[key]).length > LONG_VALUE,
                ),
        ),
    );
    const numeric = new Set(
        columns.filter((key) =>
            sample.every(
                (row) => row[key] == null || typeof row[key] === "number",
            ),
        ),
    );
    const filtered = data
        .filter((row) =>
            JSON.stringify(row).toLowerCase().includes(query.toLowerCase()),
        )
        .sort(
            (a, b) =>
                displayValue(a[sort.key]).localeCompare(
                    displayValue(b[sort.key]),
                    undefined,
                    { numeric: true },
                ) * sort.direction,
        );
    const pager = useLocalPagination(filtered.length, 25);
    const cell = (key, value) => {
        if (PROCESS_KEY.test(key)) {
            const seqids = Array.isArray(value) ? value : [value];
            const chips = seqids.slice(0, PROCESS_CHIPS).map((seqid) => {
                    const process = processes[seqid];
                    return (
                        <button
                            key={String(seqid)}
                            type="button"
                            className="btn btn-sm btn-outline-secondary me-1 mb-1 text-nowrap"
                            onClick={() => onSelect?.(seqid)}
                        >
                            {process
                                ? `${(process.procname || process.name || "process").split(/[\\/]/).pop()} (${process.pid})`
                                : displayValue(seqid)}
                        </button>
                    );
                });
            return seqids.length > PROCESS_CHIPS ? (
                <>
                    {chips}
                    <span className="text-muted small">
                        +{seqids.length - PROCESS_CHIPS} more
                    </span>
                </>
            ) : (
                chips
            );
        }
        return displayValue(value).slice(0, 1000);
    };
    return (
        <section
            aria-label={label}
            className="report-section"
            id={id}
            data-outline={id ? label : undefined}
        >
            <div className="chimera-table-toolbar">
                <h3>
                    {label}{" "}
                    <span className="badge bg-secondary">{data.length}</span>
                </h3>
                {data.length > 8 ? (
                    <input
                        aria-label={`Search ${label}`}
                        className="form-control form-control-sm"
                        placeholder={`Search ${label}`}
                        value={query}
                        onChange={(e) => {
                            setQuery(e.target.value);
                            pager.setPage(1);
                        }}
                    />
                ) : null}
            </div>
            {!data.length ? (
                <p className="report-empty-list">None reported.</p>
            ) : (
                <>
                    <div className="chimera-table-scroll">
                        <table className="table table-sm table-hover chimera-data-table">
                            <thead>
                                <tr>
                                    {columns.map((key) => (
                                        <th
                                            scope="col"
                                            key={key}
                                            aria-sort={
                                                sort.key === key
                                                    ? sort.direction > 0
                                                        ? "ascending"
                                                        : "descending"
                                                    : undefined
                                            }
                                        >
                                            <button
                                                type="button"
                                                className="chimera-sort"
                                                onClick={() =>
                                                    setSort({
                                                        key,
                                                        direction:
                                                            sort.key === key
                                                                ? -sort.direction
                                                                : 1,
                                                    })
                                                }
                                            >
                                                {key.replaceAll("_", " ")}
                                                {sort.key === key ? (
                                                    <span
                                                        className="chimera-sort-mark"
                                                        aria-hidden="true"
                                                    >
                                                        {sort.direction > 0
                                                            ? "▲"
                                                            : "▼"}
                                                    </span>
                                                ) : null}
                                            </button>
                                        </th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody>
                                {pager.slice(filtered).map((row, i) => (
                                    <tr key={pager.start + i}>
                                        {columns.map((key) => (
                                            <td
                                                key={key}
                                                className={`cell-mono ${PROCESS_KEY.test(key) ? "cell-procs" : numeric.has(key) ? "cell-num" : long.has(key) ? "cell-long" : "cell-short"}`}
                                            >
                                                {cell(key, row[key])}
                                            </td>
                                        ))}
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                    {!filtered.length ? (
                        <p className="report-empty-list mt-2">
                            No rows match the search.
                        </p>
                    ) : null}
                    {filtered.length > PAGE_SIZES[0] ? (
                        <Pagination
                            pager={pager}
                            label={`${label} pages`}
                            noun="rows"
                        />
                    ) : null}
                </>
            )}
        </section>
    );
}

const SECTIONS = [
    ["DNS", "dns_queries"],
    ["Connections", "connections"],
    ["HTTP requests", "http_requests"],
    ["TLS requests", "tls_requests"],
    ["TLS handshakes", "tls_handshakes"],
    ["TLS failures", "tls_failures"],
    ["Modified files", "modified_files"],
    ["Deleted files", "deleted_files"],
    ["Memory dumps", "memdumps"],
    ["TTPs (raw)", "ttps"],
    ["Cracked URLs", "cracked_urls"],
];

export function useAttackEntries(summary, chimeraReport) {
    return useMemo(() => {
        const scope = sampleScope(summary);
        const fromTtps = entriesFromTtps(summary?.ttps, scope);
        const system = fromTtps.filter((e) => e.source === "system");
        // The analyst report already holds the sample-tree TTPs plus static and capa capabilities.
        const sample = Array.isArray(chimeraReport?.attack)
            ? chimeraReport.attack
            : fromTtps.filter((e) => e.source === "dynamic");
        return { sample, system };
    }, [summary, chimeraReport]);
}

export function AnalysisDashboard({
    analysisId,
    summary,
    onSelect,
    isOffline,
    chimeraReport,
}) {
    const [stats, setStats] = useState(null);
    useEffect(() => {
        if (isOffline) return;
        let active = true;
        axios
            .get(`/logs/${analysisId}/stats`)
            .then((r) => {
                if (active) setStats(r.data);
            })
            .catch(() => {});
        return () => {
            active = false;
        };
    }, [analysisId, isOffline]);
    const attack = useAttackEntries(summary, chimeraReport);
    const present = useMemo(
        () => SECTIONS.filter(([, key]) => list(summary?.[key]).length),
        [summary],
    );
    const empty = SECTIONS.filter(([, key]) => !list(summary?.[key]).length);
    const outline = useMemo(
        () => [
            { id: "summary-overview", label: "Overview" },
            { id: "summary-timeline", label: "Activity timeline" },
            {
                id: "summary-attack",
                label: "MITRE ATT&CK",
                count: new Set(
                    attack.sample.map((e) => e.technique?.split(".")[0]),
                ).size,
            },
            ...present.map(([label, key]) => ({
                id: `summary-${key}`,
                label,
                count: list(summary?.[key]).length,
            })),
            ...(empty.length
                ? [{ id: "summary-empty", label: "Nothing reported", count: 0 }]
                : []),
        ],
        // eslint-disable-next-line react-hooks/exhaustive-deps
        [present, attack, summary],
    );
    if (!summary)
        return (
            <p>
                {summary === null
                    ? "Failed to load analysis summary report."
                    : "Loading analysis summary report..."}
            </p>
        );
    const counts = [
        ["Processes", Object.keys(summary.processes || {}).length],
        ["Files written", list(summary.modified_files).length],
        ["Files deleted", list(summary.deleted_files).length],
        ["Registry writes", stats?.registry_writes ?? "–"],
        ...SECTIONS.filter(
            ([, key]) =>
                ![
                    "modified_files",
                    "deleted_files",
                    "cracked_urls",
                    "tls_failures",
                    "tls_requests",
                ].includes(key),
        ).map(([name, key]) => [
            key === "ttps" ? "TTPs" : name,
            list(summary[key]).length,
        ]),
    ];
    return (
        <div>
            <SectionOutline items={outline} title="Summary outline" />
            <section
                id="summary-overview"
                data-outline="Overview"
                className="report-section"
            >
                <div className="static-metrics">
                    {counts.map(([label, value]) => (
                        <div className="card" key={label}>
                            <div className="card-body p-2">
                                <div className="small text-muted">{label}</div>
                                <strong>{value}</strong>
                            </div>
                        </div>
                    ))}
                </div>
            </section>
            <section
                id="summary-timeline"
                data-outline="Activity timeline"
                className="report-section"
            >
                <Timeline stats={stats} />
            </section>
            <section
                id="summary-attack"
                data-outline="MITRE ATT&CK"
                className="report-section"
                aria-label="MITRE ATT&CK"
            >
                <h2>MITRE ATT&CK</h2>
                <AttackMatrix
                    entries={attack.sample}
                    systemEntries={attack.system}
                />
            </section>
            {present.map(([label, key]) => (
                <ReportTable
                    key={key}
                    id={`summary-${key}`}
                    label={label}
                    rows={summary[key]}
                    processes={summary.processes}
                    onSelect={onSelect}
                />
            ))}
            {empty.length ? (
                <section
                    id="summary-empty"
                    data-outline="Nothing reported"
                    className="report-section"
                >
                    <h2>Nothing reported</h2>
                    <p className="report-empty-list">
                        {empty.map(([label]) => label).join(" · ")}
                    </p>
                </section>
            ) : null}
            <details className="mb-3">
                <summary>Startup details</summary>
                <ReportTable
                    label="Startup"
                    rows={summary.startup ? [summary.startup] : []}
                    processes={summary.processes}
                    onSelect={onSelect}
                />
            </details>
            {summary["karton-analysis-results"] && (
                <details>
                    <summary>Extracted configurations and YARA</summary>
                    <GenericBlock value={summary["karton-analysis-results"]} />
                </details>
            )}
        </div>
    );
}
export function ProcessWorkspace({
    analysisId,
    selectedProcess,
    summary,
    onSelect,
    isOffline,
    analysisStart,
}) {
    const [info, setInfo] = useState(null),
        [stats, setStats] = useState(null),
        [error, setError] = useState("");
    useEffect(() => {
        setInfo(null);
        setStats(null);
        setError("");
        if (selectedProcess == null || isOffline) return;
        const controller = new AbortController();
        axios
            .get(`/process_info/${analysisId}/${selectedProcess}`, {
                signal: controller.signal,
            })
            .then((r) => setInfo(r.data))
            .catch(() => {
                if (!controller.signal.aborted)
                    setError("Process details unavailable.");
            });
        axios
            .get(`/logs/${analysisId}/stats/process/${selectedProcess}`, {
                signal: controller.signal,
            })
            .then((r) => setStats(r.data))
            .catch(() => {});
        return () => controller.abort();
    }, [analysisId, selectedProcess, isOffline]);
    if (selectedProcess == null)
        return <p>Select a process from the process tree.</p>;
    const process = info?.process || summary?.processes?.[selectedProcess];
    const start = analysisStart
        ? Date.parse(analysisStart) / 1000
        : Number(
              stats?.analysis_first_ts ??
                  summary?.info?.start_time ??
                  stats?.first_ts ??
                  process?.ts_from,
          );
    const relative = (value) =>
        value != null && Number.isFinite(Number(value) - start)
            ? `${(Number(value) - start).toFixed(3)}s`
            : "–";
    return (
        <section aria-label="Selected process">
            {error && <p role="status">{error}</p>}
            {process ? (
                <>
                    <h5 className="text-break">
                        {process.procname}{" "}
                        <span className="font-monospace">
                            PID {process.pid}
                        </span>
                    </h5>
                    <dl className="row small">
                        {[
                            ["Path", process.procname],
                            ["PID / PPID", `${process.pid} / ${process.ppid}`],
                            [
                                "Command line",
                                Array.isArray(process.args)
                                    ? process.args.join(" ")
                                    : process.args,
                            ],
                            [
                                "Start / end",
                                `${relative(process.ts_from)} / ${process.ts_to ? relative(process.ts_to) : "running"}`,
                            ],
                            [
                                "Exit code",
                                process.exit_code_str ?? process.exit_code,
                            ],
                            ["Killed by", process.killed_by],
                            ["Children", process.children?.length ?? 0],
                        ].map(([label, value]) => (
                            <div className="col-12" key={label}>
                                <dt>{label}</dt>
                                <dd className="font-monospace text-break">
                                    {displayValue(value)}
                                </dd>
                            </div>
                        ))}
                    </dl>
                </>
            ) : (
                <p>Loading process information…</p>
            )}
            {stats && (
                <>
                    <CountChart
                        values={Object.entries(stats.logs || {})}
                        label="Process events by plugin"
                    />
                    <Timeline stats={stats} label="Process activity timeline" />
                    {Object.entries(stats.top_values || {}).map(
                        ([kind, values]) => (
                            <ReportTable
                                key={kind}
                                label={`Touched ${kind}`}
                                rows={values.map(([value, count]) => ({
                                    value,
                                    count,
                                }))}
                            />
                        ),
                    )}
                </>
            )}
            {!isOffline && (
                <LogWorkspace
                    {...{
                        analysisId,
                        selectedProcess,
                        onProcessSelect: onSelect,
                        processes: summary?.processes,
                    }}
                />
            )}
        </section>
    );
}
