import { CodeExplorer, SourceCode, GenericBlock } from "./CodeExplorer.jsx";
import { useState } from "react";
import {
    Area,
    AreaChart,
    CartesianGrid,
    ReferenceLine,
    ResponsiveContainer,
    Tooltip,
    XAxis,
    YAxis,
} from "recharts";
import { getDeepStatic, getStaticReport } from "../api.js";
import { MobsfView } from "./MobsfView.jsx";
import {
    SEVERITY_CLASS,
    StaticOverview,
    useOptionalJson,
} from "../AnalysisVerdict.jsx";
import "./static.css";
import {
    ElfDetails,
    FileLayout,
    FlaggedStrings,
    ImportsView,
    Indicators,
    PeDetails,
} from "./Insight.jsx";

const text = (value) =>
    value == null
        ? "Not reported"
        : typeof value === "object"
          ? JSON.stringify(value)
          : String(value);
export function Chips({ values = [] }) {
    return values.map((v, i) => (
        <span
            key={i}
            className="badge bg-secondary me-1 mb-1 text-wrap"
            title={
                typeof v === "object"
                    ? [
                          v.tactic,
                          v.technique,
                          v.subtechnique,
                          v.objective,
                          v.behavior,
                      ]
                          .filter(Boolean)
                          .join(" / ")
                    : undefined
            }
        >
            {v.id || text(v)}
        </span>
    ));
}
function Facts({ block = {}, keys = Object.keys(block) }) {
    return (
        <dl className="static-facts">
            {keys.map((k) => (
                <div key={k}>
                    <dt>{k.replaceAll("_", " ")}</dt>
                    <dd className="text-break font-monospace">
                        {text(block[k])}
                    </dd>
                </div>
            ))}
        </dl>
    );
}
function List({ values = [] }) {
    return values.length ? (
        <ul className="small text-break font-monospace">
            {values.map((v, i) => (
                <li key={i}>{text(v)}</li>
            ))}
        </ul>
    ) : (
        <p className="text-muted">None reported.</p>
    );
}
function Table({ label, columns, rows = [] }) {
    return (
        <div className="chimera-table-scroll mb-2">
            <table
                aria-label={label}
                className="table table-sm chimera-data-table static-table"
            >
                <thead>
                    <tr>
                        {columns.map((c) => (
                            <th scope="col" key={c}>
                                {c}
                            </th>
                        ))}
                    </tr>
                </thead>
                <tbody>
                    {rows.map((row, i) => (
                        <tr key={i}>
                            {row.map((v, j) => (
                                <td
                                    className={j ? "cell-long" : "cell-short"}
                                    key={j}
                                >
                                    {v}
                                </td>
                            ))}
                        </tr>
                    ))}
                </tbody>
            </table>
            {!rows.length && <p className="text-muted">None reported.</p>}
        </div>
    );
}
function Entropy({ value }) {
    return (
        <div className="static-entropy">
            <span>{value ?? "–"}</span>
            <meter
                aria-label="Entropy"
                min="0"
                max="8"
                high="7.2"
                optimum="0"
                value={value || 0}
            />
            {value > 7.2 && (
                <span className="badge bg-warning text-dark">
                    Packed / encrypted
                </span>
            )}
        </div>
    );
}
export function Structure({ data }) {
    if (!["pe", "elf"].includes(data.type?.format) && !data.pe && !data.elf)
        return (
            <section aria-label="Structure">
                <p>No PE or ELF structure is available for this file format.</p>
            </section>
        );
    const pe = data.pe;
    const b = pe || data.elf || {};
    const profile = data.universal?.entropy_profile;
    return (
        <section aria-label="Structure">
            <FileLayout data={data} />
            {pe ? <PeDetails pe={pe} /> : <ElfDetails elf={data.elf} />}
            <h6>Header facts</h6>
            <Facts
                block={b}
                keys={
                    pe
                        ? [
                              "timestamp_utc",
                              "subsystem",
                              "image_base",
                              "entry_point",
                              "aslr",
                              "dep",
                              "cfg",
                              "checksum_valid",
                              "dotnet",
                          ]
                        : [
                              "class",
                              "endian",
                              "type",
                              "machine",
                              "osabi",
                              "entry",
                              "interpreter",
                              "static",
                              "stripped",
                              "exec_stack",
                          ]
                }
            />
            <h6>Sections ({b.sections?.length || 0})</h6>
            <Table
                label="Sections"
                columns={[
                    "Name",
                    "Size / virtual",
                    "Raw size",
                    "Entropy",
                    "Permissions / type",
                    "Flags",
                ]}
                rows={(b.sections || []).map((s) => [
                    <span className="font-monospace">
                        {s.name}
                        {pe && s.name === pe.entry_section && (
                            <span className="badge bg-info text-dark ms-1">
                                Entry
                            </span>
                        )}
                    </span>,
                    s.virtual_size ?? s.size,
                    s.raw_size ?? "–",
                    <Entropy value={s.entropy} />,
                    pe ? (
                        <span
                            className={
                                s.w && s.x
                                    ? "text-danger fw-bold"
                                    : "font-monospace"
                            }
                        >
                            {`${s.r ? "R" : "-"}${s.w ? "W" : "-"}${s.x ? "X" : "-"}`}
                            {s.w && s.x ? " W+X" : ""}
                        </span>
                    ) : (
                        s.type
                    ),
                    (s.flags || []).length ? (
                        <span className="text-warning-emphasis">
                            {s.flags
                                .map((f) => f.replaceAll("_", " "))
                                .join(", ")}
                        </span>
                    ) : (
                        "–"
                    ),
                ])}
            />
            <h6>Entropy over file</h6>
            {profile?.series?.length ? (
                <>
                    <div
                        className="static-chart"
                        aria-label="Entropy over file chart"
                    >
                        <ResponsiveContainer width="100%" height={200}>
                            <AreaChart
                                data={profile.series.map((entropy, i) => ({
                                    entropy,
                                    offset:
                                        i *
                                        (profile.series_step_blocks || 1) *
                                        (profile.block_bytes || 4096),
                                }))}
                            >
                                <CartesianGrid strokeDasharray="3 3" />
                                <XAxis dataKey="offset" />
                                <YAxis domain={[0, 8]} />
                                <Tooltip />
                                <ReferenceLine
                                    y={7.2}
                                    stroke="var(--bs-danger)"
                                    label="7.2"
                                />
                                <Area
                                    dataKey="entropy"
                                    stroke="var(--chimera-cyan)"
                                    fill="var(--chimera-cyan)"
                                    fillOpacity={0.2}
                                />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                    <p className="small text-muted">
                        Byte offsets; each point is the highest entropy across{" "}
                        {profile.series_step_blocks || 1} blocks of{" "}
                        {profile.block_bytes} bytes.
                    </p>
                </>
            ) : (
                <p className="text-muted">
                    Entropy profile not reported by this analyzer.
                </p>
            )}
            {pe && !pe.imports_annotated ? (
                <>
                    <h6>Imports ({pe.import_count ?? 0})</h6>
                    {Object.entries(pe.import_categories || {}).map(
                        ([k, v]) => (
                            <div
                                key={k}
                                className="text-warning-emphasis small mb-1"
                            >
                                <strong>{k}: </strong>
                                {v.join(", ")}
                            </div>
                        ),
                    )}
                    {Object.entries(pe.imports || {}).map(([dll, funcs]) => (
                        <details key={dll}>
                            <summary>
                                {dll} ({funcs.length})
                            </summary>
                            <ul className="font-monospace small text-break">
                                {funcs.map((f, i) => (
                                    <li
                                        key={i}
                                        className={
                                            Object.values(
                                                pe.import_categories || {},
                                            )
                                                .flat()
                                                .includes(f)
                                                ? "text-warning-emphasis fw-bold"
                                                : ""
                                        }
                                    >
                                        {f}
                                    </li>
                                ))}
                            </ul>
                        </details>
                    ))}
                    <h6 className="mt-3">Exports ({pe.export_count ?? 0})</h6>
                    <List values={pe.exports} />
                    <h6>Resources</h6>
                    <Facts block={pe.resources} />
                    <h6>Signature</h6>
                    <Facts block={pe.signature} />
                </>
            ) : pe ? null : (
                <>
                    <h6>Symbols ({b.symbol_count ?? 0})</h6>
                    <Facts block={b.symbol_categories} />
                    <h6>Needed libraries</h6>
                    <List values={b.needed} />
                    <h6>Segments</h6>
                    <Table
                        label="Segments"
                        columns={["Type", "Flags", "File size", "Memory size"]}
                        rows={(b.segments || []).map((s) => [
                            s.type,
                            s.flags,
                            s.filesz,
                            s.memsz,
                        ])}
                    />
                </>
            )}
        </section>
    );
}
export function Strings({ data, deep }) {
    const [query, setQuery] = useState("");
    const [only, setOnly] = useState(false);
    const iocs = Object.entries(data.universal?.iocs || {}).flatMap(
        ([kind, values]) =>
            Array.isArray(values)
                ? values.map((value) => ({ kind, value }))
                : [],
    );
    const samples = [
        ...new Set([
            ...(data.universal?.strings?.sample || []),
            ...iocs.map((i) => i.value),
        ]),
    ];
    const tags = (value) => iocs.filter((i) => value.includes(i.value));
    const filter = (value) =>
        value.toLowerCase().includes(query.toLowerCase()) &&
        (!only || tags(value).length);
    const visible = samples.filter(filter);
    return (
        <section aria-label="Strings">
            <FlaggedStrings data={data} />
            <h6>All strings</h6>
            <div className="d-flex flex-wrap gap-3 mb-3">
                <label>
                    Search strings
                    <input
                        className="form-control form-control-sm"
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                    />
                </label>
                <label className="align-self-end">
                    <input
                        type="checkbox"
                        className="form-check-input me-2"
                        checked={only}
                        onChange={(e) => setOnly(e.target.checked)}
                    />
                    IOCs only
                </label>
            </div>
            <p className="small text-muted">
                {data.universal?.strings?.ascii ?? 0} ASCII /{" "}
                {data.universal?.strings?.utf16 ?? 0} UTF-16 · {visible.length}{" "}
                displayed from capped samples
            </p>
            <ul className="static-string-list font-monospace small text-break">
                {visible.map((s, i) => (
                    <li key={i}>
                        {tags(s).length ? <mark>{s}</mark> : s}
                        <Chips
                            values={[...new Set(tags(s).map((t) => t.kind))]}
                        />
                    </li>
                ))}
            </ul>
            {!visible.length && <p>No strings match.</p>}
            {["stack", "tight", "decoded"].map((kind) => (
                <details open key={kind}>
                    <summary>
                        {kind[0].toUpperCase() + kind.slice(1)} strings (
                        {deep?.floss?.[kind]?.count ?? 0})
                    </summary>
                    <List
                        values={(deep?.floss?.[kind]?.sample || []).filter(
                            filter,
                        )}
                    />
                </details>
            ))}
        </section>
    );
}
export const TACTICS = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
];
export function AttackMatrix({ rules = [] }) {
    const columns = TACTICS.map((tactic) => ({
        tactic,
        entries: rules.flatMap((r) =>
            (r.attack || [])
                .filter(
                    (a) =>
                        typeof a === "object" &&
                        a.tactic?.toLowerCase() === tactic.toLowerCase(),
                )
                .map((a) => ({ ...a, rule: r.name })),
        ),
    })).filter((c) => c.entries.length);
    return (
        <section aria-label="ATT&CK matrix">
            <h6>ATT&amp;CK matrix</h6>
            {columns.length ? (
                <div className="static-matrix">
                    {columns.map((c) => (
                        <div key={c.tactic} className="card">
                            <div className="card-header small fw-bold">
                                {c.tactic}
                            </div>
                            <div className="card-body p-2">
                                {[...new Set(c.entries.map((e) => e.id))].map(
                                    (id) => {
                                        const entries = c.entries.filter(
                                            (e) => e.id === id,
                                        );
                                        return (
                                            <div
                                                className="border rounded p-2 mb-1 small text-break"
                                                key={id}
                                                title={entries
                                                    .map((e) => e.rule)
                                                    .join("\n")}
                                            >
                                                {id}
                                                <br />
                                                {entries[0].subtechnique ||
                                                    entries[0].technique}
                                            </div>
                                        );
                                    },
                                )}
                            </div>
                        </div>
                    ))}
                </div>
            ) : (
                <p className="text-muted">
                    No tactic metadata reported. Older results retain technique
                    IDs below.
                </p>
            )}
        </section>
    );
}
function CapabilityTree({ rules, depth = 0 }) {
    const groups = rules.reduce((groups, rule) => {
        const key =
            (rule.namespace || "Uncategorized").split("/")[depth] || "Other";
        (groups[key] ||= []).push(rule);
        return groups;
    }, Object.create(null));
    return Object.entries(groups).map(([namespace, items]) => (
        <details open key={namespace}>
            <summary>
                {namespace} ({items.length})
            </summary>
            {items
                .filter(
                    (r) =>
                        (r.namespace || "Uncategorized").split("/").length <=
                        depth + 1,
                )
                .map((r, i) => (
                    <article
                        key={i}
                        className="border-start ps-3 py-2 text-break"
                    >
                        <strong>{r.name}</strong>
                        <div className="small text-muted">
                            {r.namespace} · {r.matches ?? 0} matches
                        </div>
                        <Chips values={r.attack} />
                        <Chips values={r.mbc} />
                    </article>
                ))}
            {items.some(
                (r) => (r.namespace || "").split("/").length > depth + 1,
            ) && (
                <div className="ps-2">
                    <CapabilityTree
                        rules={items.filter(
                            (r) =>
                                (r.namespace || "").split("/").length >
                                depth + 1,
                        )}
                        depth={depth + 1}
                    />
                </div>
            )}
        </details>
    ));
}
export function Capabilities({ data, deep }) {
    const rules = deep?.capa?.rules || [];
    return (
        <section aria-label="Capabilities">
            <h6>
                capa capabilities ({deep?.capa?.rules_total ?? rules.length})
            </h6>
            <AttackMatrix rules={rules} />
            {deep?.capa && (
                <p className="small text-muted">
                    capa {deep.capa.version}
                    {deep.capa.library_signatures
                        ? ""
                        : " · library code not filtered: no signatures"}
                </p>
            )}
            <CapabilityTree rules={rules} />
            {!rules.length && (
                <p className="text-muted">No capabilities reported.</p>
            )}
            <section aria-label="YARA matches" className="card mt-3">
                <div className="card-body">
                    <h6>YARA matches ({data.universal?.yara?.length || 0})</h6>
                    <Table
                        label="YARA matches"
                        columns={["Rule", "Severity", "Description"]}
                        rows={(data.universal?.yara || []).map((y) => {
                            const severity =
                                data.findings?.find(
                                    (f) => f.id === `yara_${y.rule}`,
                                )?.severity ||
                                y.meta?.severity ||
                                "medium";
                            return [
                                y.rule,
                                <span
                                    className={`badge ${SEVERITY_CLASS[severity] || "bg-secondary"}`}
                                >
                                    {severity}
                                </span>,
                                text(y.meta?.description),
                            ];
                        })}
                    />
                </div>
            </section>
        </section>
    );
}

export function HighlightedCode(props) {
    return <SourceCode {...props} />;
}
export function Code(props) {
    return <CodeExplorer {...props} />;
}
export function FormatDetails({ data }) {
    const fmt = data.type?.format;
    const b = data[fmt];
    if (!b) return <p>Format details not reported.</p>;
    if (!["zip", "apk", "pdf", "ole", "ooxml"].includes(fmt))
        return (
            <section aria-label="Format details">
                <h6>{fmt}</h6>
                <GenericBlock value={b} />
            </section>
        );
    if (fmt === "zip") {
        const flagged = [
            ...(b.executables || []),
            ...(b.scripts || []),
            ...(b.nested_archives || []),
        ];
        return (
            <section aria-label="Format details">
                <h6>ZIP members ({b.members})</h6>
                <Facts
                    block={b}
                    keys={[
                        "uncompressed_bytes",
                        "compression_ratio",
                        "encrypted",
                        "truncated",
                        "comment",
                    ]}
                />
                <Table
                    label="ZIP members"
                    columns={[
                        "Name",
                        "Size",
                        "Compressed",
                        "Encrypted",
                        "Flagged",
                    ]}
                    rows={(b.listed || []).map((m) => [
                        m.name,
                        m.size,
                        m.compressed,
                        text(m.encrypted),
                        flagged.includes(m.name) ||
                        m.encrypted ||
                        /(^[\\/]|^[a-z]:|(?:^|[\\/])\.\.(?:[\\/]|$))/i.test(
                            m.name,
                        ) ? (
                            <span className="badge bg-warning text-dark">
                                Review
                            </span>
                        ) : (
                            "–"
                        ),
                    ])}
                />
            </section>
        );
    }
    if (fmt === "apk")
        return (
            <section aria-label="Format details">
                <h6>Android package</h6>
                <Facts
                    block={b}
                    keys={[
                        "package",
                        "app_name",
                        "version_name",
                        "version_code",
                        "min_sdk",
                        "target_sdk",
                        "main_activity",
                        "dex_count",
                        "signature_verification",
                        "signature_error",
                    ]}
                />
                <h6>Permissions</h6>
                <ul className="small text-break">
                    {(b.permissions || []).map((p) => (
                        <li
                            key={p}
                            className={
                                b.dangerous_permissions?.includes(p)
                                    ? "text-danger fw-bold"
                                    : ""
                            }
                        >
                            {p}
                            {b.dangerous_permissions?.includes(p) &&
                                " · dangerous"}
                        </li>
                    ))}
                </ul>
                {["activities", "services", "receivers", "providers"].map(
                    (k) => (
                        <details key={k}>
                            <summary>
                                {k} ({b[k]?.count ?? 0})
                            </summary>
                            <List values={b[k]?.names} />
                        </details>
                    ),
                )}
                <h6>Exported components</h6>
                <Table
                    label="Exported components"
                    columns={["Type", "Name", "Permission"]}
                    rows={(b.exported_components || []).map((c) => [
                        c.type,
                        c.name,
                        c.permission || "None",
                    ])}
                />
                <h6>Certificates</h6>
                <Table
                    label="Certificates"
                    columns={["Subject", "Issuer", "SHA-256", "Debug"]}
                    rows={(b.certificates || []).map((c) => [
                        c.subject,
                        c.issuer,
                        <span className="font-monospace">{c.sha256}</span>,
                        text(c.debug),
                    ])}
                />
                <Facts block={b.signature_schemes} />
                <h6>Native libraries</h6>
                <List values={b.native_libraries} />
                <h6>DEX URLs</h6>
                <List values={b.urls} />
                <h6>Executable assets</h6>
                <List values={b.asset_payloads} />
                <h6>DEX scans skipped</h6>
                <List values={b.dex_scan_skipped} />
            </section>
        );
    return (
        <section aria-label="Format details">
            <h6>{fmt === "pdf" ? "PDF keywords" : "Office macros"}</h6>
            <Facts
                block={b}
                keys={
                    fmt === "pdf"
                        ? [
                              "version",
                              "header_offset",
                              "objects",
                              "endobj",
                              "streams",
                              "xref",
                              "trailer",
                              "eof_markers",
                              "obfuscated_names",
                          ]
                        : ["macros", "xlm", "encoded_strings"]
                }
            />
            {fmt === "pdf" ? (
                <>
                    <Table
                        label="PDF keywords"
                        columns={["Keyword", "Count"]}
                        rows={Object.entries(b.keywords || {})}
                    />
                    <h6>URIs</h6>
                    <List values={b.uris} />
                </>
            ) : (
                [
                    "modules",
                    "autoexec",
                    "suspicious",
                    "iocs",
                    "external_relationships",
                ].map((k) => (
                    <div key={k}>
                        <h6>
                            {k === "autoexec"
                                ? "Auto-execution"
                                : k === "suspicious"
                                  ? "Suspicious calls"
                                  : k.replaceAll("_", " ")}
                        </h6>
                        {k === "external_relationships" ? (
                            <Table
                                label="External relationships"
                                columns={["Part", "Type", "Target"]}
                                rows={(b[k] || []).map((r) => [
                                    r.part,
                                    r.type,
                                    r.target,
                                ])}
                            />
                        ) : (
                            <List values={b[k]} />
                        )}
                    </div>
                ))
            )}
        </section>
    );
}
function DeepStatus({ state }) {
    return (
        <div className="small text-muted mb-3" role="status">
            {state.loading
                ? "Loading deep analysis…"
                : state.missing
                  ? state.polling
                      ? "Not run yet: capa and FLOSS run after the fast pass (this updates by itself)."
                      : "No deep pass for this analysis (off on this server, or it has not finished)."
                  : state.error
                    ? `Deep analysis error: ${state.error}`
                    : state.data?.error
                      ? `Deep pass failed: ${state.data.error}`
                      : "Deep analysis available."}
            {state.data?.errors?.map((e, i) => (
                <div key={i} className="text-warning-emphasis">
                    {e.stage}: {e.error}
                </div>
            ))}
        </div>
    );
}
const noDeep = () => Promise.resolve(null);
function Workspace({ data, analysisId }) {
    const [tab, setTab] = useState("Overview");
    const fmt = data.type?.format;
    const supported = ["pe", "elf"].includes(fmt);
    const deepState = useOptionalJson(
        supported ? getDeepStatic : noDeep,
        analysisId,
    );
    const deep = deepState.data;
    const formatTab = Object.keys(data).some(
        (key) =>
            ![
                "schema",
                "type",
                "file",
                "universal",
                "findings",
                "coverage",
                "score",
                "level",
                "container",
                "duration_s",
                "analyzer_version",
                "source",
                "error",
            ].includes(key) &&
            data[key] &&
            typeof data[key] === "object",
    );
    const indicatorCount = data.indicators?.length || 0;
    const tabs = [
        "Overview",
        ...(indicatorCount ? ["Indicators"] : []),
        "Structure",
        ...(supported ? ["Imports"] : []),
        ...(fmt === "apk" ? ["Android (MobSF)"] : []),
        "Strings",
        "Capabilities",
        "Code",
        ...(formatTab ? ["Format details"] : []),
    ];
    const tabLabel = (t) =>
        t === "Indicators"
            ? `Indicators (${indicatorCount})`
            : t === "Imports" && (data.pe || data.elf)?.imports_summary
              ? `Imports (${(data.pe || data.elf).imports_summary.total_count ?? 0})`
              : t;
    const hidden = ["stack", "tight", "decoded"].reduce(
        (n, k) => n + (deep?.floss?.[k]?.count || 0),
        0,
    );
    return (
        <div className="static-workspace">
            <nav
                aria-label="Static analysis sections"
                className="nav nav-pills gap-1 mb-3"
            >
                {tabs.map((t) => (
                    <button
                        type="button"
                        key={t}
                        className={`nav-link ${tab === t ? "active" : ""}`}
                        aria-pressed={tab === t}
                        onClick={() => setTab(t)}
                    >
                        {tabLabel(t)}
                    </button>
                ))}
            </nav>
            {supported && <DeepStatus state={deepState} />}
            {tab === "Overview" && (
                <>
                    <div className="static-metrics mb-3">
                        {[
                            [
                                "Assessment",
                                `${data.level || "unknown"} · ${data.score ?? "–"}/100`,
                            ],
                            ["File size", `${data.file?.size ?? "–"} bytes`],
                            [
                                "Entropy",
                                <Entropy value={data.universal?.entropy} />,
                            ],
                            [
                                "Signature",
                                data.pe?.signature?.present === false
                                    ? "Unsigned"
                                    : data.pe?.signature?.present
                                      ? data.pe.signature.valid
                                          ? "Signed · verified"
                                          : "Signed · unverified"
                                      : "Not reported",
                            ],
                            ["YARA hits", data.universal?.yara?.length ?? 0],
                            [
                                "Indicators",
                                data.indicators_summary
                                    ? `${data.indicators_summary.high} high · ${data.indicators_summary.medium} medium · ${data.indicators_summary.low} low`
                                    : "–",
                            ],
                            [
                                "capa capabilities",
                                deep?.capa?.rules_total ?? "–",
                            ],
                            ["Hidden strings", deep?.floss ? hidden : "–"],
                        ].map(([label, value]) => (
                            <div className="card" key={label}>
                                <div className="card-body p-3">
                                    <div className="small text-muted">
                                        {label}
                                    </div>
                                    <div
                                        className={`fw-semibold text-break ${label === "Assessment" ? `text-${data.level === "high" ? "danger" : data.level === "medium" || data.level === "low" ? "warning-emphasis" : "body"}` : ""}`}
                                    >
                                        {value}
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                    <StaticOverview
                        data={{
                            ...data,
                            findings: [...(data.findings || [])].sort(
                                (a, b) =>
                                    [
                                        "critical",
                                        "high",
                                        "medium",
                                        "low",
                                        "info",
                                    ].indexOf(a.severity) -
                                    [
                                        "critical",
                                        "high",
                                        "medium",
                                        "low",
                                        "info",
                                    ].indexOf(b.severity),
                            ),
                        }}
                    />
                </>
            )}
            {tab === "Indicators" && <Indicators data={data} />}
            {tab === "Structure" && <Structure data={data} />}
            {tab === "Imports" && <ImportsView data={data} />}
            {tab === "Android (MobSF)" && <MobsfView analysisId={analysisId} />}
            {tab === "Strings" && <Strings data={data} deep={deep} />}
            {tab === "Capabilities" && <Capabilities data={data} deep={deep} />}
            {tab === "Code" && (
                <Code deep={deep} format={fmt} source={data.source} />
            )}
            {tab === "Format details" && (
                <>
                    {["pdf", "ole", "ooxml", "zip", "apk"].includes(fmt) && (
                        <FormatDetails data={data} />
                    )}
                    {Object.entries(data)
                        .filter(
                            ([key, value]) =>
                                ![
                                    "schema",
                                    "type",
                                    "file",
                                    "universal",
                                    "findings",
                                    "coverage",
                                    "score",
                                    "level",
                                    "container",
                                    "duration_s",
                                    "analyzer_version",
                                    "source",
                                    "error",
                                    ...([
                                        "pdf",
                                        "ole",
                                        "ooxml",
                                        "zip",
                                        "apk",
                                    ].includes(fmt)
                                        ? [fmt]
                                        : []),
                                ].includes(key) &&
                                value &&
                                typeof value === "object",
                        )
                        .map(([key, value]) => (
                            <section
                                key={key}
                                aria-label={`${key} format details`}
                                className="mb-3"
                            >
                                <h6>{key}</h6>
                                <GenericBlock value={value} />
                            </section>
                        ))}
                </>
            )}
        </div>
    );
}
export default function StaticWorkspace({ analysisId }) {
    const state = useOptionalJson(getStaticReport, analysisId);
    let message = state.loading
        ? "Loading static analysis..."
        : state.missing
          ? state.polling
              ? "No static analysis yet: waiting for static analysis (this updates by itself)."
              : "No static analysis for this analysis (static analysis was off, or it has not finished)."
          : state.error
            ? `Error: ${state.error}`
            : state.data?.error
              ? `Static analysis failed: ${state.data.error}`
              : null;
    return (
        <div className="static-shell py-2">
            {message ? (
                <div role="status">{message}</div>
            ) : (
                <Workspace
                    key={analysisId}
                    data={state.data}
                    analysisId={analysisId}
                />
            )}
        </div>
    );
}
