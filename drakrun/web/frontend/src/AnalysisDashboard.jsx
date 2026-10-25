import { useEffect, useState } from "react";
import axios from "axios";
import {
    Timeline,
    CountChart,
    LogWorkspace,
    displayValue,
} from "./StructuredLogs.jsx";
import { GenericBlock } from "./static/CodeExplorer.jsx";

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
export function ReportTable({ label, rows, processes = {}, onSelect }) {
    const [query, setQuery] = useState(""),
        [page, setPage] = useState(0),
        [sort, setSort] = useState({ key: "", direction: 1 });
    const data = list(rows).map((value) =>
        typeof value === "object" && value !== null ? value : { value },
    );
    const keys = [...new Set(data.slice(0, 100).flatMap(Object.keys))];
    const columns = [
        ...keys.filter((key) => /process/.test(key)),
        ...keys.filter((key) => !/process/.test(key)),
    ].slice(0, 12);
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
    const cell = (key, value) => {
        if (
            /^(process|processes|process_seqid|process_seqids|processSeqid|target_process)$/.test(
                key,
            )
        )
            return (Array.isArray(value) ? value : [value])
                .slice(0, 50)
                .map((id) => {
                    const process = processes[id];
                    return (
                        <button
                            key={String(id)}
                            className="btn btn-sm btn-outline-secondary me-1 text-break"
                            onClick={() => onSelect?.(id)}
                        >
                            {process
                                ? `${(process.procname || process.name || "process").split(/[\\/]/).pop()} (${process.pid})`
                                : displayValue(id)}
                        </button>
                    );
                });
        return displayValue(value).slice(0, 1000);
    };
    return (
        <section aria-label={label} className="mb-4">
            <h6>
                {label}{" "}
                <span className="badge bg-secondary">{data.length}</span>
            </h6>
            <input
                aria-label={`Search ${label}`}
                className="form-control form-control-sm mb-2"
                placeholder={`Search ${label}`}
                value={query}
                onChange={(e) => {
                    setQuery(e.target.value);
                    setPage(0);
                }}
            />
            <div className="table-responsive">
                <table className="table table-sm analysis-event-table">
                    <thead>
                        <tr>
                            {columns.map((key) => (
                                <th scope="col" key={key}>
                                    <button
                                        className="btn btn-sm btn-inline-link"
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
                                    </button>
                                </th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {filtered
                            .slice(page * 25, page * 25 + 25)
                            .map((row, i) => (
                                <tr key={i}>
                                    {columns.map((key) => (
                                        <td
                                            key={key}
                                            className="text-break small font-monospace"
                                        >
                                            {cell(key, row[key])}
                                        </td>
                                    ))}
                                </tr>
                            ))}
                    </tbody>
                </table>
            </div>
            {!data.length && <p className="small text-muted">None reported.</p>}
            {filtered.length > 25 && (
                <div className="d-flex gap-2">
                    <button
                        className="btn btn-sm btn-outline-secondary"
                        disabled={!page}
                        onClick={() => setPage(page - 1)}
                    >
                        Previous
                    </button>
                    <span>
                        {page + 1} / {Math.ceil(filtered.length / 25)}
                    </span>
                    <button
                        className="btn btn-sm btn-outline-secondary"
                        disabled={(page + 1) * 25 >= filtered.length}
                        onClick={() => setPage(page + 1)}
                    >
                        Next
                    </button>
                </div>
            )}
        </section>
    );
}
export function AnalysisDashboard({
    analysisId,
    summary,
    onSelect,
    isOffline,
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
    if (!summary)
        return (
            <p>
                {summary === null
                    ? "Failed to load analysis summary report."
                    : "Loading analysis summary report..."}
            </p>
        );
    const sections = [
        ["DNS", "dns_queries"],
        ["Connections", "connections"],
        ["HTTP requests", "http_requests"],
        ["TLS requests", "tls_requests"],
        ["TLS handshakes", "tls_handshakes"],
        ["TLS failures", "tls_failures"],
        ["Modified files", "modified_files"],
        ["Deleted files", "deleted_files"],
        ["Memory dumps", "memdumps"],
        ["TTPs / ATT&CK", "ttps"],
        ["Cracked URLs", "cracked_urls"],
    ];
    const counts = [
        ["Processes", Object.keys(summary.processes || {}).length],
        ["Files written", list(summary.modified_files).length],
        ["Files deleted", list(summary.deleted_files).length],
        ["Registry writes", stats?.registry_writes ?? "–"],
        ...sections
            .filter(
                ([, key]) =>
                    ![
                        "modified_files",
                        "deleted_files",
                        "cracked_urls",
                        "tls_failures",
                        "tls_requests",
                    ].includes(key),
            )
            .map(([name, key]) => [name, list(summary[key]).length]),
    ];
    return (
        <div>
            <div className="static-metrics mb-3">
                {counts.map(([label, value]) => (
                    <div className="card" key={label}>
                        <div className="card-body p-2">
                            <div className="small text-muted">{label}</div>
                            <strong>{value}</strong>
                        </div>
                    </div>
                ))}
            </div>
            <Timeline stats={stats} />
            <details className="mb-3">
                <summary>Startup details</summary>
                <ReportTable
                    label="Startup"
                    rows={summary.startup ? [summary.startup] : []}
                    processes={summary.processes}
                    onSelect={onSelect}
                />
            </details>
            {sections.map(([label, key]) => (
                <ReportTable
                    key={key}
                    label={label}
                    rows={summary[key]}
                    processes={summary.processes}
                    onSelect={onSelect}
                />
            ))}
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
