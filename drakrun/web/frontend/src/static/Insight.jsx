import { useMemo, useState } from "react";
import { PAGE_SIZES, Pagination, useLocalPagination } from "../Pagination.jsx";
import { attackUrl, techniqueName } from "../AttackMatrix.jsx";

// PEStudio-style views of the static analyzer's insight data (chimera-static/1): indicators, annotated imports,
// file and memory layout, header details and flagged strings, for PE and ELF.

export const SEVERITY = {
    3: { label: "high", className: "bg-danger" },
    2: { label: "medium", className: "bg-warning text-dark" },
    1: { label: "low", className: "bg-info text-dark" },
    0: { label: "none", className: "bg-secondary" },
};

export const hex = (value) =>
    typeof value === "number" && Number.isFinite(value)
        ? `0x${value.toString(16)}`
        : "–";

export function formatBytes(value) {
    if (typeof value !== "number") return "–";
    if (value < 1024) return `${value} B`;
    if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
    return `${(value / 1024 / 1024).toFixed(1)} MiB`;
}

export function SeverityBadge({ value }) {
    const severity = SEVERITY[value] || SEVERITY[0];
    return (
        <span className={`badge ${severity.className}`}>{severity.label}</span>
    );
}

function Attack({ ids = [] }) {
    if (!ids?.length) return "–";
    return ids.map((id) => (
        <a
            key={id}
            className="badge bg-secondary me-1 text-decoration-none"
            href={attackUrl(id)}
            target="_blank"
            rel="noopener noreferrer"
            title={techniqueName(id)}
        >
            {id}
        </a>
    ));
}

const label = (value) => String(value || "").replaceAll("_", " ");

function SortHeader({ id, children, sort, setSort }) {
    const active = sort.key === id;
    return (
        <th
            scope="col"
            aria-sort={
                active ? (sort.dir > 0 ? "ascending" : "descending") : undefined
            }
        >
            <button
                type="button"
                className="chimera-sort"
                onClick={() =>
                    setSort({
                        key: id,
                        dir: active ? -sort.dir : id === "severity" ? -1 : 1,
                    })
                }
            >
                {children}
                {active ? (
                    <span className="chimera-sort-mark" aria-hidden="true">
                        {sort.dir > 0 ? "▲" : "▼"}
                    </span>
                ) : null}
            </button>
        </th>
    );
}

function compare(key, dir) {
    return (a, b) => {
        const x = a[key];
        const y = b[key];
        const order =
            typeof x === "number" && typeof y === "number"
                ? x - y
                : String(x ?? "").localeCompare(String(y ?? ""), undefined, {
                      numeric: true,
                  });
        return (
            order * dir ||
            String(a.name ?? a.title ?? "").localeCompare(
                String(b.name ?? b.title ?? ""),
            )
        );
    };
}

function Pager({ pager, noun, label: name }) {
    return pager.total > PAGE_SIZES[0] ? (
        <Pagination pager={pager} label={name} noun={noun} />
    ) : null;
}

// ---------------------------------------------------------------------------
// Indicators
// ---------------------------------------------------------------------------

export function Indicators({ data }) {
    const items = data.indicators || [];
    const [levels, setLevels] = useState({ 3: true, 2: true, 1: true });
    const [category, setCategory] = useState("");
    const [query, setQuery] = useState("");
    const [sort, setSort] = useState({ key: "severity", dir: -1 });
    const categories = [...new Set(items.map((i) => i.category))].sort();
    const shown = items
        .filter(
            (i) =>
                levels[i.severity] &&
                (!category || i.category === category) &&
                `${i.title} ${i.detail} ${i.evidence} ${(i.attack || []).join(" ")}`
                    .toLowerCase()
                    .includes(query.toLowerCase()),
        )
        .sort(compare(sort.key, sort.dir));
    const pager = useLocalPagination(shown.length, 25);
    const summary = data.indicators_summary || {};
    if (!items.length)
        return (
            <section aria-label="Indicators">
                <p className="text-muted">
                    No indicators: this analyzer version does not report them,
                    or nothing stood out in the file.
                </p>
            </section>
        );
    return (
        <section aria-label="Indicators">
            <div className="chimera-table-toolbar">
                {[3, 2, 1].map((level) => (
                    <label
                        key={level}
                        className="form-check form-check-inline m-0"
                    >
                        <input
                            className="form-check-input"
                            type="checkbox"
                            checked={levels[level]}
                            onChange={(e) => {
                                setLevels({
                                    ...levels,
                                    [level]: e.target.checked,
                                });
                                pager.setPage(1);
                            }}
                        />
                        <span className="form-check-label">
                            <SeverityBadge value={level} />{" "}
                            {summary[SEVERITY[level].label] ??
                                items.filter((i) => i.severity === level)
                                    .length}
                        </span>
                    </label>
                ))}
                <select
                    className="form-select form-select-sm w-auto"
                    aria-label="Indicator category"
                    value={category}
                    onChange={(e) => {
                        setCategory(e.target.value);
                        pager.setPage(1);
                    }}
                >
                    <option value="">All categories</option>
                    {categories.map((c) => (
                        <option key={c} value={c}>
                            {label(c)}
                        </option>
                    ))}
                </select>
                <input
                    className="form-control form-control-sm"
                    aria-label="Search indicators"
                    placeholder="Search indicators"
                    value={query}
                    onChange={(e) => {
                        setQuery(e.target.value);
                        pager.setPage(1);
                    }}
                />
            </div>
            <p className="small text-muted">
                Observations about the file, most severe first. They are not
                proof of behaviour on their own: the verdict weighs them with
                the run.
            </p>
            <div className="chimera-table-scroll">
                <table className="table table-sm table-hover chimera-data-table">
                    <thead>
                        <tr>
                            <SortHeader
                                id="severity"
                                sort={sort}
                                setSort={setSort}
                            >
                                Severity
                            </SortHeader>
                            <SortHeader
                                id="category"
                                sort={sort}
                                setSort={setSort}
                            >
                                Category
                            </SortHeader>
                            <SortHeader
                                id="title"
                                sort={sort}
                                setSort={setSort}
                            >
                                Indicator
                            </SortHeader>
                            <th scope="col">Detail</th>
                            <th scope="col">Evidence</th>
                            <th scope="col">ATT&CK</th>
                        </tr>
                    </thead>
                    <tbody>
                        {pager.slice(shown).map((i, n) => (
                            <tr key={`${i.id}-${i.evidence}-${n}`}>
                                <td className="cell-short">
                                    <SeverityBadge value={i.severity} />
                                </td>
                                <td className="cell-short">
                                    {label(i.category)}
                                </td>
                                <td className="cell-long fw-semibold">
                                    {i.title}
                                </td>
                                <td className="cell-long">
                                    {i.detail && i.detail !== i.title
                                        ? i.detail
                                        : "–"}
                                </td>
                                <td className="cell-long cell-mono">
                                    {i.evidence || "–"}
                                </td>
                                <td className="cell-short">
                                    <Attack ids={i.attack} />
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
            {!shown.length ? (
                <p className="report-empty-list mt-2">No indicator matches.</p>
            ) : null}
            <Pager pager={pager} noun="indicators" label="Indicator pages" />
        </section>
    );
}

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

function flattenImports(block, isPe) {
    if (isPe)
        return (block.imports_annotated || []).flatMap((lib) =>
            (lib.functions || []).map((fn) => ({
                ...fn,
                name: fn.name || `#${fn.ordinal}`,
                library: lib.dll,
            })),
        );
    return (block.imports_annotated || []).map((fn) => ({
        ...fn,
        library: fn.lib || "",
    }));
}

const worstOf = (lib) =>
    Math.max(0, ...(lib.functions || []).map((f) => f.severity || 0));

export function ImportsView({ data }) {
    const isPe = !!data.pe;
    const block = data.pe || data.elf || {};
    const all = useMemo(() => flattenImports(block, isPe), [block, isPe]);
    const libraries = isPe ? block.imports_annotated || [] : [];
    const [library, setLibrary] = useState("");
    const [category, setCategory] = useState("");
    const [flagged, setFlagged] = useState(false);
    const [query, setQuery] = useState("");
    const [sort, setSort] = useState({ key: "severity", dir: -1 });
    const summary = block.imports_summary || {};
    const categories = Object.entries(summary.categories || {}).sort(
        (a, b) => b[1] - a[1],
    );
    const shown = all
        .filter(
            (fn) =>
                (!library || fn.library === library) &&
                (!category || fn.category === category) &&
                (!flagged || fn.severity > 0) &&
                `${fn.name} ${fn.library} ${fn.description} ${fn.attacker_use}`
                    .toLowerCase()
                    .includes(query.toLowerCase()),
        )
        .sort(compare(sort.key, sort.dir));
    const pager = useLocalPagination(shown.length, 50);
    const reset = () => pager.setPage(1);
    if (!all.length)
        return (
            <section aria-label="Imports">
                <p className="text-muted">
                    {isPe || data.elf
                        ? "No annotated imports: the file imports nothing, or this analyzer version does not annotate them."
                        : "Imports are reported for PE and ELF files."}
                </p>
            </section>
        );
    return (
        <section aria-label="Imports">
            <div className="static-import-summary">
                <div>
                    <strong>{summary.total_count ?? all.length}</strong>
                    <span>
                        {isPe ? "imported functions" : "imported symbols"}
                    </span>
                </div>
                <div>
                    <strong>
                        {summary.flagged_count ??
                            all.filter((f) => f.severity > 0).length}
                    </strong>
                    <span>worth a look (severity 1+)</span>
                </div>
                <div>
                    <strong>{all.filter((f) => f.severity >= 2).length}</strong>
                    <span>suspicious in context (2+)</span>
                </div>
                {isPe ? (
                    <div>
                        <strong>{libraries.length}</strong>
                        <span>libraries</span>
                    </div>
                ) : null}
            </div>
            <div className="static-chip-row" aria-label="Import categories">
                {categories.map(([name, count]) => (
                    <button
                        key={name}
                        type="button"
                        className={`static-chip ${category === name ? "is-active" : ""}`}
                        aria-pressed={category === name}
                        onClick={() => {
                            setCategory(category === name ? "" : name);
                            reset();
                        }}
                    >
                        {label(name)} <span>{count}</span>
                    </button>
                ))}
            </div>
            <div className={isPe ? "static-imports-layout" : ""}>
                {isPe ? (
                    <nav className="static-libraries" aria-label="Libraries">
                        <button
                            type="button"
                            aria-pressed={!library}
                            className={!library ? "is-active" : ""}
                            onClick={() => {
                                setLibrary("");
                                reset();
                            }}
                        >
                            <span className="fw-semibold">All libraries</span>
                            <span className="badge bg-secondary">
                                {all.length}
                            </span>
                        </button>
                        {[...libraries]
                            .sort(
                                (a, b) =>
                                    worstOf(b) - worstOf(a) ||
                                    a.dll.localeCompare(b.dll),
                            )
                            .map((lib) => (
                                <button
                                    key={lib.dll}
                                    type="button"
                                    aria-pressed={library === lib.dll}
                                    className={
                                        library === lib.dll ? "is-active" : ""
                                    }
                                    title={lib.description || undefined}
                                    onClick={() => {
                                        setLibrary(lib.dll);
                                        reset();
                                    }}
                                >
                                    <span className="font-monospace text-break">
                                        {lib.dll}
                                    </span>
                                    <span className="d-flex gap-1 align-items-center">
                                        {worstOf(lib) ? (
                                            <SeverityBadge
                                                value={worstOf(lib)}
                                            />
                                        ) : null}
                                        <span className="badge bg-secondary">
                                            {lib.functions?.length || 0}
                                        </span>
                                    </span>
                                    {lib.description ? (
                                        <span className="static-lib-note">
                                            {lib.description}
                                        </span>
                                    ) : null}
                                </button>
                            ))}
                    </nav>
                ) : null}
                <div className="min-width-0">
                    <div className="chimera-table-toolbar">
                        <label className="form-check m-0">
                            <input
                                className="form-check-input"
                                type="checkbox"
                                checked={flagged}
                                onChange={(e) => {
                                    setFlagged(e.target.checked);
                                    reset();
                                }}
                            />
                            <span className="form-check-label">
                                Flagged only
                            </span>
                        </label>
                        <input
                            className="form-control form-control-sm"
                            aria-label="Search imports"
                            placeholder="Search name, library or purpose"
                            value={query}
                            onChange={(e) => {
                                setQuery(e.target.value);
                                reset();
                            }}
                        />
                    </div>
                    <div className="chimera-table-scroll">
                        <table className="table table-sm table-hover chimera-data-table">
                            <thead>
                                <tr>
                                    <SortHeader
                                        id="severity"
                                        sort={sort}
                                        setSort={setSort}
                                    >
                                        Severity
                                    </SortHeader>
                                    <SortHeader
                                        id="name"
                                        sort={sort}
                                        setSort={setSort}
                                    >
                                        {isPe ? "Function" : "Symbol"}
                                    </SortHeader>
                                    {isPe ? (
                                        <SortHeader
                                            id="library"
                                            sort={sort}
                                            setSort={setSort}
                                        >
                                            Library
                                        </SortHeader>
                                    ) : null}
                                    <SortHeader
                                        id="category"
                                        sort={sort}
                                        setSort={setSort}
                                    >
                                        Category
                                    </SortHeader>
                                    <th scope="col">What it does</th>
                                    <th scope="col">Why malware uses it</th>
                                    <th scope="col">ATT&CK</th>
                                </tr>
                            </thead>
                            <tbody>
                                {pager.slice(shown).map((fn, n) => (
                                    <tr key={`${fn.library}!${fn.name}!${n}`}>
                                        <td className="cell-short">
                                            {fn.severity ? (
                                                <SeverityBadge
                                                    value={fn.severity}
                                                />
                                            ) : (
                                                "–"
                                            )}
                                        </td>
                                        <td className="cell-short cell-mono fw-semibold">
                                            {fn.name}
                                            {fn.by_ordinal ? (
                                                <span className="text-muted ms-1">
                                                    (by ordinal)
                                                </span>
                                            ) : null}
                                        </td>
                                        {isPe ? (
                                            <td className="cell-short cell-mono">
                                                {fn.library}
                                            </td>
                                        ) : null}
                                        <td className="cell-short">
                                            {label(fn.category)}
                                        </td>
                                        <td className="cell-long">
                                            {fn.description || "–"}
                                        </td>
                                        <td className="cell-long">
                                            {fn.attacker_use || "–"}
                                        </td>
                                        <td className="cell-short">
                                            {fn.severity >= 2 ? (
                                                <Attack ids={fn.attack} />
                                            ) : (
                                                "–"
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                    {!shown.length ? (
                        <p className="report-empty-list mt-2">
                            No import matches.
                        </p>
                    ) : null}
                    <Pager
                        pager={pager}
                        noun={isPe ? "functions" : "symbols"}
                        label="Import pages"
                    />
                    {summary.truncated ? (
                        <p className="small text-warning-emphasis">
                            The list is capped; the file has more imports than
                            shown.
                        </p>
                    ) : null}
                    <p className="small text-muted mt-2">
                        Purpose and attacker use come from CHIMERA&apos;s
                        offline API knowledge base. ATT&amp;CK ids are shown
                        only for APIs suspicious in context; an import alone
                        does not prove the behaviour.
                    </p>
                </div>
            </div>
            <Exports block={block} isPe={isPe} />
        </section>
    );
}

function Exports({ block, isPe }) {
    const exports = block.exports_annotated || [];
    const pager = useLocalPagination(exports.length, 25);
    if (!exports.length) return null;
    return (
        <section aria-label="Exports" className="mt-4">
            <h6>Exports ({block.export_count ?? exports.length})</h6>
            <div className="chimera-table-scroll">
                <table className="table table-sm chimera-data-table">
                    <thead>
                        <tr>
                            <th scope="col">Name</th>
                            <th scope="col">{isPe ? "Ordinal" : "Type"}</th>
                            <th scope="col">{isPe ? "RVA" : "Value"}</th>
                            <th scope="col">
                                {isPe ? "Forwarded to" : "Size"}
                            </th>
                            <th scope="col">Note</th>
                        </tr>
                    </thead>
                    <tbody>
                        {pager.slice(exports).map((e, n) => (
                            <tr key={`${e.name}-${n}`}>
                                <td className="cell-short cell-mono fw-semibold">
                                    {e.name || "–"}
                                </td>
                                <td className="cell-short">
                                    {isPe ? (e.ordinal ?? "–") : e.type}
                                </td>
                                <td className="cell-short cell-mono">
                                    {hex(isPe ? e.rva : e.value)}
                                </td>
                                <td className="cell-short cell-mono">
                                    {isPe ? e.forwarded || "–" : e.size}
                                </td>
                                <td className="cell-long">
                                    {e.flagged
                                        ? "Shares a Windows API name (proxy or wrapper library?)"
                                        : "–"}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
            <Pager pager={pager} noun="exports" label="Export pages" />
        </section>
    );
}

// ---------------------------------------------------------------------------
// File and memory layout
// ---------------------------------------------------------------------------

function LayoutBar({ regions, total, ariaLabel, kindOf }) {
    const min = total * 0.012;
    return (
        <div className="static-layout-bar" role="img" aria-label={ariaLabel}>
            {regions.map((r, i) => {
                const size = Math.max(r.size || 0, 0);
                return (
                    <div
                        key={`${r.name}-${i}`}
                        className={`static-layout-part is-${kindOf(r)}`}
                        style={{ flexGrow: Math.max(size, min), flexBasis: 0 }}
                        title={`${r.name}: ${formatBytes(size)} at ${hex(r.offset ?? r.rva)}${typeof r.entropy === "number" ? `, entropy ${r.entropy.toFixed(2)}` : ""}`}
                    >
                        <span>{r.name}</span>
                    </div>
                );
            })}
        </div>
    );
}

const fileKind = (r) =>
    r.kind === "section" && /^LOAD /.test(r.name) ? "gap" : r.kind || "section";
const memoryKind = (r) => (r.w && r.x ? "wx" : r.x ? "x" : r.w ? "w" : "r");

export function FileLayout({ data }) {
    const block = data.pe || data.elf || {};
    const layout = block.layout || [];
    const memory = block.memory_layout || [];
    if (!layout.length && !memory.length) return null;
    const fileSize =
        data.file?.size ||
        layout.reduce(
            (end, r) => Math.max(end, (r.offset || 0) + (r.size || 0)),
            0,
        );
    const memorySize = memory.reduce(
        (end, r) => Math.max(end, (r.rva || 0) + (r.virtual_size || 0)),
        0,
    );
    return (
        <section aria-label="File layout" className="static-layout">
            <h6>File layout on disk ({formatBytes(fileSize)})</h6>
            <LayoutBar
                regions={layout}
                total={fileSize}
                ariaLabel="File layout: headers, sections and overlay by offset"
                kindOf={fileKind}
            />
            <div className="static-layout-legend small">
                {[
                    ["header", "Headers"],
                    ["section", "Section"],
                    ["overlay", "Overlay (appended data)"],
                    ["certificate", "Certificate"],
                    ["gap", "Gap / padding"],
                ].map(([kind, text]) => (
                    <span key={kind}>
                        <i className={`is-${kind}`} aria-hidden="true" />
                        {text}
                    </span>
                ))}
            </div>
            <div
                className="chimera-table-scroll mt-2"
                style={{ maxHeight: "22rem" }}
            >
                <table className="table table-sm chimera-data-table">
                    <thead>
                        <tr>
                            <th scope="col">Region</th>
                            <th scope="col">Kind</th>
                            <th scope="col">Offset</th>
                            <th scope="col">Size</th>
                            <th scope="col">Share</th>
                            <th scope="col">Entropy</th>
                        </tr>
                    </thead>
                    <tbody>
                        {layout.map((r, i) => (
                            <tr key={`${r.name}-${i}`}>
                                <td className="cell-short cell-mono fw-semibold">
                                    {r.name}
                                </td>
                                <td className="cell-short">{fileKind(r)}</td>
                                <td className="cell-num cell-mono">
                                    {hex(r.offset)}
                                </td>
                                <td className="cell-num">
                                    {formatBytes(r.size)}
                                </td>
                                <td className="cell-num">
                                    {fileSize
                                        ? `${((100 * (r.size || 0)) / fileSize).toFixed(1)}%`
                                        : "–"}
                                </td>
                                <td className="cell-short">
                                    {typeof r.entropy === "number" ? (
                                        <span
                                            className={
                                                r.entropy > 7.2
                                                    ? "text-danger fw-bold"
                                                    : ""
                                            }
                                        >
                                            {r.entropy.toFixed(2)}
                                            {r.entropy > 7.2
                                                ? " packed / encrypted?"
                                                : ""}
                                        </span>
                                    ) : (
                                        "–"
                                    )}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
            {memory.length ? (
                <>
                    <h6 className="mt-3">
                        Memory layout when loaded ({formatBytes(memorySize)})
                    </h6>
                    <LayoutBar
                        regions={memory.map((r) => ({
                            ...r,
                            size: r.virtual_size,
                        }))}
                        total={memorySize}
                        ariaLabel="Memory layout by permissions"
                        kindOf={memoryKind}
                    />
                    <div className="static-layout-legend small">
                        {[
                            ["r", "Read only"],
                            ["w", "Writable"],
                            ["x", "Executable"],
                            ["wx", "Writable and executable (suspicious)"],
                        ].map(([kind, text]) => (
                            <span key={kind}>
                                <i
                                    className={`is-${kind}`}
                                    aria-hidden="true"
                                />
                                {text}
                            </span>
                        ))}
                    </div>
                </>
            ) : null}
        </section>
    );
}

// ---------------------------------------------------------------------------
// Header details (PE) and ELF details
// ---------------------------------------------------------------------------

function show(value) {
    if (value === null || value === "" || value === undefined) return "–";
    if (Array.isArray(value))
        return value.length ? value.map(label).join(", ") : "none";
    if (typeof value === "boolean") return value ? "yes" : "no";
    if (typeof value === "object") return JSON.stringify(value);
    return String(value);
}

function Facts({ rows }) {
    return (
        <dl className="static-facts">
            {rows
                .filter(([, value]) => value !== undefined)
                .map(([name, value]) => (
                    <div key={name}>
                        <dt>{name}</dt>
                        <dd className="text-break font-monospace">
                            {show(value)}
                        </dd>
                    </div>
                ))}
        </dl>
    );
}

function SimpleTable({ label: name, columns, rows, empty = "None reported." }) {
    if (!rows.length) return <p className="small text-muted">{empty}</p>;
    return (
        <div className="chimera-table-scroll" style={{ maxHeight: "24rem" }}>
            <table
                className="table table-sm chimera-data-table"
                aria-label={name}
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
                            {row.map((cell, j) => (
                                <td
                                    key={j}
                                    className={
                                        j === 0
                                            ? "cell-short cell-mono"
                                            : "cell-long"
                                    }
                                >
                                    {cell ?? "–"}
                                </td>
                            ))}
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

export function PeDetails({ pe }) {
    if (!pe?.headers) return null;
    const { dos = {}, file = {}, optional = {} } = pe.headers;
    const directories =
        pe.headers.data_directories || optional.data_directories || [];
    const cert = pe.certificate || {};
    const strings = (pe.version_details?.string_tables || []).flatMap((table) =>
        Object.entries(table.entries || table.strings || table || {}).filter(
            ([, v]) => typeof v === "string",
        ),
    );
    return (
        <section aria-label="PE header details" className="static-details">
            <details open>
                <summary>DOS and file header</summary>
                <Facts
                    rows={[
                        ["DOS stub", dos.stub_message],
                        ["Standard stub", dos.standard_stub],
                        ["e_lfanew", hex(dos.e_lfanew)],
                        ["Machine", file.machine_name],
                        ["Sections", file.number_of_sections],
                        ["Compile time (UTC)", file.timestamp_utc],
                        ["Time flags", file.timestamp_flags],
                        ["Characteristics", file.characteristics],
                    ]}
                />
            </details>
            <details open>
                <summary>Optional header</summary>
                <Facts
                    rows={[
                        ["Magic", optional.magic],
                        ["Linker", optional.linker_version],
                        ["OS version", optional.os_version],
                        ["Subsystem", optional.subsystem],
                        [
                            "Entry point",
                            `${hex(optional.entry_point)} in ${optional.entry_section || "?"}`,
                        ],
                        ["Image base", hex(optional.image_base)],
                        ["Size of image", formatBytes(optional.size_of_image)],
                        ["Size of code", formatBytes(optional.size_of_code)],
                        [
                            "Section / file alignment",
                            `${hex(optional.section_alignment)} / ${hex(optional.file_alignment)}`,
                        ],
                        ["DLL characteristics", optional.dll_characteristics],
                        [
                            "Checksum",
                            pe.checksum_valid === undefined
                                ? undefined
                                : pe.checksum_valid
                                  ? "valid"
                                  : "mismatch or zero",
                        ],
                    ]}
                />
            </details>
            {directories.length ? (
                <details>
                    <summary>
                        Data directories (
                        {directories.filter((d) => d.present).length} present)
                    </summary>
                    <SimpleTable
                        label="Data directories"
                        columns={["Directory", "RVA", "Size", "Present"]}
                        rows={directories.map((d) => [
                            d.name,
                            hex(d.rva),
                            formatBytes(d.size),
                            d.present ? "yes" : "no",
                        ])}
                    />
                </details>
            ) : null}
            <details>
                <summary>Signature</summary>
                <Facts
                    rows={[
                        ["Signed", cert.present],
                        ["Verified", cert.verified],
                        ["Why", cert.reason],
                        ["Signer", cert.signer],
                        ["Issuer", cert.issuer],
                        ["Serial", cert.serial],
                        ["Valid from", cert.not_before],
                        ["Valid until", cert.not_after],
                        ["Thumbprint", cert.thumbprint],
                        ["Counter-signed", cert.counter_signature_time],
                    ]}
                />
            </details>
            <details>
                <summary>Version information</summary>
                {strings.length ? (
                    <Facts rows={strings} />
                ) : (
                    <p className="small text-muted">No version resource.</p>
                )}
                {pe.version_flags?.original_filename_mismatch ? (
                    <p className="small text-warning-emphasis">
                        OriginalFilename differs from the uploaded name.
                    </p>
                ) : null}
                {pe.version_flags?.company_present_unsigned ? (
                    <p className="small text-warning-emphasis">
                        Names a company but carries no signature.
                    </p>
                ) : null}
            </details>
            <details>
                <summary>Manifest</summary>
                {pe.manifest ? (
                    <Facts
                        rows={[
                            [
                                "Requested execution level",
                                pe.manifest.requested_execution_level ??
                                    pe.manifest.execution_level,
                            ],
                            ["UI access", pe.manifest.ui_access],
                            ["Supported OS", pe.manifest.supported_os],
                            ["Dependencies", pe.manifest.dependencies],
                        ]}
                    />
                ) : (
                    <p className="small text-muted">No manifest.</p>
                )}
            </details>
            <details>
                <summary>
                    Resources ({(pe.resources_annotated || []).length})
                </summary>
                <SimpleTable
                    label="Resources"
                    columns={[
                        "Type",
                        "Name / id",
                        "Language",
                        "Size",
                        "Entropy",
                        "Content",
                        "SHA-256",
                    ]}
                    rows={(pe.resources_annotated || []).map((r) => [
                        r.type,
                        String(r.name ?? r.id ?? "–"),
                        r.language,
                        formatBytes(r.size),
                        typeof r.entropy === "number"
                            ? r.entropy.toFixed(2)
                            : "–",
                        r.magic || r.content_type,
                        r.sha256 ? (
                            <span className="font-monospace">{r.sha256}</span>
                        ) : (
                            "–"
                        ),
                    ])}
                    empty="No resources."
                />
            </details>
            <details>
                <summary>Debug, Rich header, TLS, load config</summary>
                <SimpleTable
                    label="Debug directory"
                    columns={["Type", "PDB path", "GUID / age", "Flags"]}
                    rows={(pe.debug || []).map((d) => [
                        d.type,
                        d.pdb_path,
                        d.guid ? `${d.guid} / ${d.age ?? "–"}` : "–",
                        (d.flags || []).map(label).join(", ") || "–",
                    ])}
                    empty="No debug directory."
                />
                {pe.rich_header_details?.present ? (
                    <SimpleTable
                        label="Rich header"
                        columns={["Product id", "Product", "Build", "Count"]}
                        rows={(pe.rich_header_details.entries || []).map(
                            (r) => [r.product_id, r.product, r.build, r.count],
                        )}
                    />
                ) : (
                    <p className="small text-muted">No Rich header.</p>
                )}
                <Facts
                    rows={[
                        ["TLS callbacks", (pe.tls?.callbacks || []).map(hex)],
                        [
                            "Security cookie",
                            hex(pe.load_config?.security_cookie),
                        ],
                        ["CFG functions", pe.load_config?.cfg_function_count],
                        ["SEH handlers", pe.load_config?.seh_handler_count],
                    ]}
                />
            </details>
            {(pe.overlay_regions || []).length ? (
                <details open>
                    <summary>Overlay</summary>
                    <SimpleTable
                        label="Overlay"
                        columns={[
                            "Offset",
                            "Size",
                            "Share",
                            "Entropy",
                            "Looks like",
                        ]}
                        rows={pe.overlay_regions.map((o) => [
                            hex(o.offset),
                            formatBytes(o.size),
                            o.percent != null ? `${o.percent}%` : "–",
                            typeof o.entropy === "number"
                                ? o.entropy.toFixed(2)
                                : "–",
                            o.magic || o.installer || "–",
                        ])}
                    />
                </details>
            ) : null}
        </section>
    );
}

export function ElfDetails({ elf }) {
    if (!elf?.header && !elf?.security) return null;
    const h = elf.header || {};
    const s = elf.security || {};
    return (
        <section aria-label="ELF details" className="static-details">
            <details open>
                <summary>Header and hardening</summary>
                <Facts
                    rows={[
                        ["Class", h.class ? `${h.class}-bit` : undefined],
                        ["Byte order", h.data],
                        ["OS / ABI", h.osabi],
                        ["Type", h.type],
                        ["Machine", h.machine],
                        ["Entry", hex(h.entry)],
                        ["Interpreter", elf.interpreter],
                        ["Languages", elf.languages],
                        ["PIE", s.pie],
                        ["NX stack", s.nx],
                        ["RELRO", s.relro],
                        ["Stack canary", s.stack_canary],
                        ["FORTIFY", s.fortify],
                        ["Stripped", s.stripped],
                    ]}
                />
            </details>
            <details>
                <summary>Dynamic section</summary>
                <Facts
                    rows={[
                        ["Needed", elf.dynamic?.needed ?? elf.needed],
                        ["RPATH", elf.dynamic?.rpath],
                        ["RUNPATH", elf.dynamic?.runpath],
                        ["BIND_NOW", elf.dynamic?.bind_now],
                    ]}
                />
            </details>
            <details>
                <summary>
                    Program headers ({(elf.program_headers || []).length})
                </summary>
                <SimpleTable
                    label="Program headers"
                    columns={[
                        "Type",
                        "Flags",
                        "Offset",
                        "Virtual address",
                        "File size",
                        "Memory size",
                    ]}
                    rows={(elf.program_headers || []).map((p) => [
                        p.type,
                        p.flags,
                        hex(p.offset),
                        hex(p.vaddr),
                        formatBytes(p.filesz),
                        formatBytes(p.memsz),
                    ])}
                />
            </details>
        </section>
    );
}

// ---------------------------------------------------------------------------
// Flagged strings
// ---------------------------------------------------------------------------

export function FlaggedStrings({ data }) {
    const rows = data.universal?.strings_flagged || [];
    const [category, setCategory] = useState("");
    const [query, setQuery] = useState("");
    const shown = rows.filter(
        (r) =>
            (!category || r.category === category) &&
            String(r.value).toLowerCase().includes(query.toLowerCase()),
    );
    const pager = useLocalPagination(shown.length, 25);
    if (!rows.length) return null;
    const counts = data.universal?.strings_summary || {};
    return (
        <section aria-label="Flagged strings" className="mb-4">
            <h6>Flagged strings ({rows.length})</h6>
            <div className="static-chip-row">
                {Object.entries(counts)
                    .sort((a, b) => b[1] - a[1])
                    .map(([name, count]) => (
                        <button
                            key={name}
                            type="button"
                            className={`static-chip ${category === name ? "is-active" : ""}`}
                            aria-pressed={category === name}
                            onClick={() => {
                                setCategory(category === name ? "" : name);
                                pager.setPage(1);
                            }}
                        >
                            {label(name)} <span>{count}</span>
                        </button>
                    ))}
            </div>
            <div className="chimera-table-toolbar">
                <input
                    className="form-control form-control-sm"
                    aria-label="Search flagged strings"
                    placeholder="Search flagged strings"
                    value={query}
                    onChange={(e) => {
                        setQuery(e.target.value);
                        pager.setPage(1);
                    }}
                />
            </div>
            <div className="chimera-table-scroll">
                <table className="table table-sm chimera-data-table">
                    <thead>
                        <tr>
                            <th scope="col">Severity</th>
                            <th scope="col">Category</th>
                            <th scope="col">String</th>
                            <th scope="col">Offset</th>
                            <th scope="col">Encoding</th>
                        </tr>
                    </thead>
                    <tbody>
                        {pager.slice(shown).map((r, i) => (
                            <tr key={`${r.offset}-${i}`}>
                                <td className="cell-short">
                                    <SeverityBadge value={r.severity} />
                                </td>
                                <td className="cell-short">
                                    {label(r.category)}
                                </td>
                                <td className="cell-long cell-mono">
                                    {r.value}
                                </td>
                                <td className="cell-num cell-mono">
                                    {hex(r.offset)}
                                </td>
                                <td className="cell-short">{r.encoding}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
            <Pager pager={pager} noun="strings" label="Flagged string pages" />
            {data.universal?.strings_flagged_truncated ? (
                <p className="small text-muted">
                    The most severe 600 are kept; the file has more flagged
                    strings.
                </p>
            ) : null}
        </section>
    );
}
