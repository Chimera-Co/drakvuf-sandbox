import { useCallback, useEffect, useRef, useState } from "react";
import axios from "axios";
import Select from "react-select";
import { getLogLoader, LogViewer } from "./LogViewer.jsx";
import {
    BarChart,
    Bar,
    XAxis,
    YAxis,
    Tooltip,
    ResponsiveContainer,
    LineChart,
    Line,
    Legend,
} from "recharts";

export const displayValue = (value) =>
    value == null
        ? "–"
        : typeof value === "object"
          ? JSON.stringify(value)
          : String(value);
const fields = {
    apimon: [
        ["Arguments", "Arguments", "Args", "DllName"],
        ["Return value", "ReturnValue", "Return", "Status"],
    ],
    regmon: [
        ["Key", "Key"],
        ["Value name", "ValueName"],
        ["Value", "Value"],
    ],
    filetracer: [["File", "FileName", "File"]],
    procmon: [
        ["Child", "NewPID", "ChildPID", "RunningProcess"],
        ["Command line", "CommandLine", "Command", "Arguments"],
    ],
    socketmon: [
        ["Local", "LocalIp", "LocalAddress"],
        ["Local port", "LocalPort"],
        ["Remote", "RemoteIp", "RemoteAddress"],
        ["Port", "RemotePort"],
        ["Protocol", "Protocol"],
    ],
    tlsmon: [
        ["Local", "LocalIp"],
        ["Remote", "RemoteIp", "ServerName", "Host"],
        ["Protocol", "Protocol", "Version"],
        ["Status", "Status"],
    ],
    exmon: [
        ["Exception", "ExceptionCode"],
        ["Address", "RIP"],
        ["First chance", "FirstChance"],
    ],
    memdump: [
        ["File", "DumpFilename"],
        ["Address", "DumpAddr"],
        ["Size", "DumpSize"],
        ["Reason", "DumpReason"],
    ],
    cpuidmon: [
        ["Leaf", "Leaf"],
        ["Subleaf", "Subleaf"],
        ["RAX", "RAX"],
        ["RBX", "RBX"],
    ],
    inject: [
        ["Target PID", "InjectedPid", "TargetPID"],
        ["Arguments", "Arguments"],
        ["Status", "Status"],
    ],
};
export function StructuredTable({
    rows = [],
    logType,
    onProcessSelect,
    processes = {},
}) {
    const [query, setQuery] = useState("");
    const [methods, setMethods] = useState([]);
    const [page, setPage] = useState(0);
    const [detail, setDetail] = useState(null);
    const [sort, setSort] = useState({ key: "TimeStamp", direction: 1 });
    useEffect(() => {
        setPage(0);
        setDetail(null);
    }, [rows]);
    const columns = [
        ["Time", "TimeStamp", "timestamp"],
        ["Process", "ProcessName", "RunningProcess", "PID"],
        ["Method", "Method", "Event"],
        ...(fields[logType] || [["Fields", "*"]]),
    ];
    const filtered = rows
        .filter(
            (row) =>
                (!methods.length ||
                    methods.some(
                        ({ value }) =>
                            value === (row.Method || row.Event || "unknown"),
                    )) &&
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
    const options = [
        ...new Set(rows.map((r) => r.Method || r.Event || "unknown")),
    ]
        .slice(0, 200)
        .map((value) => ({ value, label: value }));
    return (
        <section aria-label={`${logType} events`}>
            <div className="d-flex gap-2 mb-2 flex-wrap">
                <input
                    className="form-control form-control-sm w-auto"
                    aria-label="Search events"
                    placeholder="Search loaded events"
                    value={query}
                    onChange={(e) => {
                        setQuery(e.target.value);
                        setPage(0);
                    }}
                />
                <div style={{ minWidth: 220 }}>
                    <Select
                        aria-label="Methods"
                        isMulti
                        options={options}
                        value={methods}
                        onChange={(value) => {
                            setMethods(value);
                            setPage(0);
                        }}
                    />
                </div>
                <span className="small text-muted">
                    {filtered.length} loaded matches
                </span>
            </div>
            <div className="table-responsive">
                <table className="table table-sm table-hover analysis-event-table">
                    <thead>
                        <tr>
                            {columns.map(([label, key]) => (
                                <th scope="col" key={label}>
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
                                        {label}
                                    </button>
                                </th>
                            ))}
                            <th scope="col">Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {filtered
                            .slice(page * 50, page * 50 + 50)
                            .map((row, index) => (
                                <tr key={index}>
                                    {columns.map(([label, ...keys]) => {
                                        const value =
                                            keys[0] === "*"
                                                ? row
                                                : keys
                                                      .map((key) => row[key])
                                                      .find((v) => v != null);
                                        const seqid =
                                            row.seqid ??
                                            row.SeqId ??
                                            Object.keys(processes).find(
                                                (id) =>
                                                    processes[id].pid ===
                                                    row.PID,
                                            );
                                        return (
                                            <td
                                                key={label}
                                                className="text-break font-monospace small"
                                            >
                                                {label === "Process" &&
                                                seqid != null &&
                                                onProcessSelect ? (
                                                    <button
                                                        className="btn btn-sm btn-outline-secondary text-break"
                                                        onClick={() =>
                                                            onProcessSelect(
                                                                seqid,
                                                            )
                                                        }
                                                    >
                                                        {displayValue(value)
                                                            .split(/[/\\]/)
                                                            .pop()}{" "}
                                                        ({row.PID})
                                                    </button>
                                                ) : (
                                                    displayValue(value).slice(
                                                        0,
                                                        500,
                                                    )
                                                )}
                                            </td>
                                        );
                                    })}
                                    <td>
                                        <button
                                            className="btn btn-sm btn-outline-secondary"
                                            onClick={() => setDetail(row)}
                                        >
                                            Inspect
                                        </button>
                                    </td>
                                </tr>
                            ))}
                    </tbody>
                </table>
            </div>
            <div className="d-flex gap-2">
                <button
                    className="btn btn-sm btn-outline-secondary"
                    disabled={!page}
                    onClick={() => setPage(page - 1)}
                >
                    Previous
                </button>
                <span>Page {page + 1}</span>
                <button
                    className="btn btn-sm btn-outline-secondary"
                    disabled={(page + 1) * 50 >= filtered.length}
                    onClick={() => setPage(page + 1)}
                >
                    Next
                </button>
            </div>
            {detail && (
                <aside
                    role="dialog"
                    aria-label="Event details"
                    className="analysis-drawer border rounded p-3 bg-body"
                >
                    <button
                        autoFocus
                        className="btn btn-sm btn-secondary float-end"
                        onClick={() => setDetail(null)}
                    >
                        Close details
                    </button>
                    <h6>Event details</h6>
                    <pre
                        className="text-break"
                        style={{ whiteSpace: "pre-wrap" }}
                    >
                        {JSON.stringify(detail, null, 2)}
                    </pre>
                </aside>
            )}
        </section>
    );
}
export function Timeline({ stats, label = "Activity timeline" }) {
    if (!stats?.histogram)
        return (
            <p className="text-muted small">Activity statistics unavailable.</p>
        );
    const { counts = [], bucket_s = 1, series } = stats.histogram;
    const keys = series ? Object.keys(series) : ["events"];
    const data = counts.map((value, index) => ({
        seconds: Number((index * bucket_s).toFixed(3)),
        events: value,
        ...Object.fromEntries(
            keys.map((key) => [key, series?.[key]?.[index] ?? value]),
        ),
    }));
    const colors = ["#446baf", "#b74c53", "#19856c", "#9e72ba", "#bd842c"];
    return (
        <section aria-label={label}>
            <h6>{label}</h6>
            <div style={{ height: 210, minWidth: 0 }}>
                <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={data}>
                        <XAxis
                            dataKey="seconds"
                            label={{
                                value: "Seconds from first event",
                                position: "insideBottom",
                                offset: -3,
                            }}
                        />
                        <YAxis width={45} />
                        <Tooltip />
                        <Legend />
                        {keys.map((key, i) => (
                            <Line
                                key={key}
                                dataKey={key}
                                stroke={colors[i % colors.length]}
                                dot={false}
                                isAnimationActive={false}
                            />
                        ))}
                    </LineChart>
                </ResponsiveContainer>
            </div>
        </section>
    );
}
export function CountChart({ values = [], label = "Methods" }) {
    return (
        <section aria-label={label}>
            <h6>{label}</h6>
            <div style={{ height: 180 }}>
                <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                        data={values
                            .slice(0, 10)
                            .map(([name, count]) => ({ name, count }))}
                    >
                        <XAxis dataKey="name" hide />
                        <YAxis width={45} />
                        <Tooltip />
                        <Bar
                            dataKey="count"
                            fill="#446baf"
                            isAnimationActive={false}
                        />
                    </BarChart>
                </ResponsiveContainer>
            </div>
            <div className="small text-break">
                {values
                    .slice(0, 10)
                    .map(([name, count]) => `${name}: ${count}`)
                    .join(" · ")}
            </div>
        </section>
    );
}
export function StructuredLogViewer({
    analysisId,
    logType,
    selectedProcess,
    onProcessSelect,
    processes,
}) {
    const [rows, setRows] = useState([]),
        [plain, setPlain] = useState(""),
        [raw, setRaw] = useState(false),
        [error, setError] = useState(""),
        [stats, setStats] = useState(null),
        [done, setDone] = useState(false),
        [loading, setLoading] = useState(false),
        [search, setSearch] = useState("");
    const decoder = useRef(new TextDecoder());
    const cursor = useRef(0),
        pending = useRef(""),
        active = useRef(0);
    const path = `/logs/${analysisId}/${logType}${selectedProcess != null ? `/process/${selectedProcess}` : ""}`;
    const textLog = ["drakrun", "drakvuf_stderr"].includes(logType);
    const load = useCallback(async () => {
        const generation = active.current;
        setLoading(true);
        try {
            const response = await axios.get(path, {
                responseType: "arraybuffer",
                headers: {
                    Range: `bytes=${cursor.current}-${cursor.current + 262143}`,
                },
            });
            if (generation !== active.current) return;
            const bytes = new Uint8Array(response.data);
            const text = decoder.current.decode(bytes, { stream: true });
            cursor.current += bytes.length;
            const range = response.headers?.["content-range"];
            const end =
                (selectedProcess == null && response.status !== 206) ||
                bytes.length < 262144 ||
                (range && cursor.current >= Number(range.split("/")[1]));
            const parts = (pending.current + text).split("\n");
            pending.current = end ? "" : parts.pop();
            if (pending.current.length > 1048576) {
                pending.current = "";
                setError("An oversized event was skipped.");
            }
            if (textLog) setPlain((old) => (old + text).slice(-1048576));
            else
                setRows((current) => {
                    const parsed = parts.filter(Boolean).map((line) => {
                        try {
                            const r = JSON.parse(line);
                            return r && typeof r === "object"
                                ? r
                                : { Value: r };
                        } catch {
                            return { ParseError: line };
                        }
                    });
                    return parsed.length ? parsed : current;
                });
            setDone(Boolean(end));
        } catch (err) {
            if (generation === active.current) {
                if (err.response?.status === 416) setDone(true);
                else setError("Unable to load events.");
            }
        } finally {
            if (generation === active.current) setLoading(false);
        }
    }, [path, textLog, selectedProcess]);
    useEffect(() => {
        active.current++;
        decoder.current = new TextDecoder();
        cursor.current = 0;
        pending.current = "";
        setRows([]);
        setPlain("");
        setDone(false);
        setError("");
        setStats(null);
        load();
        const generation = active.current;
        axios
            .get(`/logs/${analysisId}/${logType}/stats`)
            .then((r) => {
                if (generation === active.current) setStats(r.data);
            })
            .catch(() => {});
        return () => {
            active.current++;
        };
    }, [load, analysisId, logType]);
    const factory = useCallback(
        () =>
            getLogLoader({
                getLogEntries: async ({ rangeStart, rangeEnd }) =>
                    (
                        await axios.get(path, {
                            responseType: "text",
                            headers: {
                                Range: `bytes=${rangeStart}-${rangeEnd}`,
                            },
                        })
                    ).data,
            }),
        [path],
    );
    return (
        <div>
            <label className="form-check mb-2">
                <input
                    type="checkbox"
                    className="form-check-input"
                    checked={raw}
                    onChange={(e) => setRaw(e.target.checked)}
                />{" "}
                Raw view
            </label>
            {error && (
                <p role="status" className="text-danger">
                    {error}
                </p>
            )}
            {raw ? (
                <LogViewer logLoaderFactory={factory} />
            ) : (
                <>
                    {selectedProcess == null && (
                        <div className="row">
                            <div className="col-lg-7">
                                <Timeline stats={stats} />
                            </div>
                            <div className="col-lg-5">
                                <CountChart values={stats?.methods} />
                            </div>
                        </div>
                    )}
                    {textLog ? (
                        <>
                            <input
                                aria-label="Search text log"
                                className="form-control"
                                value={search}
                                onChange={(e) => setSearch(e.target.value)}
                            />
                            <pre
                                className="text-break"
                                style={{
                                    whiteSpace: "pre-wrap",
                                    maxHeight: 600,
                                    overflow: "auto",
                                }}
                            >
                                {plain
                                    .split("\n")
                                    .filter((line) =>
                                        line
                                            .toLowerCase()
                                            .includes(search.toLowerCase()),
                                    )
                                    .slice(0, 1000)
                                    .map((line, i) => (
                                        <div
                                            key={i}
                                            className={
                                                /ERROR|CRITICAL/.test(line)
                                                    ? "text-danger"
                                                    : /WARN/.test(line)
                                                      ? "text-warning-emphasis"
                                                      : ""
                                            }
                                        >
                                            {line}
                                        </div>
                                    ))}
                            </pre>
                        </>
                    ) : (
                        <StructuredTable
                            key={path}
                            rows={rows}
                            logType={logType}
                            onProcessSelect={onProcessSelect}
                            processes={processes}
                        />
                    )}
                    <button
                        className="btn btn-sm btn-primary mt-3"
                        disabled={loading || done}
                        onClick={load}
                    >
                        {loading
                            ? "Loading…"
                            : done
                              ? "End of log"
                              : "Load next chunk"}
                    </button>
                    <span className="small ms-2 text-muted">
                        Showing current chunk; filters apply to loaded events.
                    </span>
                </>
            )}
        </div>
    );
}
export function LogWorkspace({
    analysisId,
    selectedProcess,
    onProcessSelect,
    processes,
    onFilterProcess,
}) {
    const [types, setTypes] = useState([]),
        [type, setType] = useState(""),
        [totals, setTotals] = useState({}),
        [error, setError] = useState("");
    useEffect(() => {
        let active = true;
        axios
            .get(`/logs/${analysisId}`)
            .then((r) => {
                if (!active) return;
                const list = r.data
                    .filter((v) => v.endsWith(".log"))
                    .map((v) => v.slice(0, -4));
                setTypes(list);
                setType(list[0] || "");
            })
            .catch(() => {
                if (active) setError("Unable to load log list.");
            });
        axios
            .get(
                selectedProcess != null
                    ? `/logs/${analysisId}/stats/process/${selectedProcess}`
                    : `/logs/${analysisId}/stats`,
            )
            .then((r) => {
                if (active) setTotals(r.data.logs || {});
            })
            .catch(() => {});
        return () => {
            active = false;
        };
    }, [analysisId, selectedProcess]);
    return (
        <div>
            {onFilterProcess && (
                <label className="d-block mb-2 small">
                    Process filter
                    <select
                        className="form-select form-select-sm"
                        aria-label="Process filter"
                        value={selectedProcess ?? ""}
                        onChange={(e) =>
                            onFilterProcess(
                                e.target.value === ""
                                    ? undefined
                                    : e.target.value,
                            )
                        }
                    >
                        <option value="">All processes</option>
                        {Object.entries(processes || {})
                            .slice(0, 500)
                            .map(([id, p]) => (
                                <option key={id} value={id}>
                                    {(p.procname || p.name || "process")
                                        .split(/[\\/]/)
                                        .pop()}{" "}
                                    ({p.pid})
                                </option>
                            ))}
                    </select>
                </label>
            )}
            {error && <p role="alert">{error}</p>}
            <div className="d-flex gap-2 flex-wrap mb-3" aria-label="Log types">
                {types.slice(0, 100).map((name) => (
                    <button
                        key={name}
                        aria-pressed={name === type}
                        className={`btn btn-sm ${name === type ? "btn-primary" : "btn-outline-secondary"}`}
                        onClick={() => setType(name)}
                    >
                        {name}{" "}
                        <span className="badge bg-secondary">
                            {totals[name] ?? "–"}
                        </span>
                    </button>
                ))}
            </div>
            {type && (
                <StructuredLogViewer
                    key={`${type}-${selectedProcess}`}
                    {...{
                        analysisId,
                        logType: type,
                        selectedProcess,
                        onProcessSelect,
                        processes,
                    }}
                />
            )}
        </div>
    );
}
