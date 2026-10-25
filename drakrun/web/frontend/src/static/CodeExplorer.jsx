import { useState } from "react";
import { tokenize } from "./highlight.js";

export function SourceCode({
    code = "",
    language = "c",
    label = "Decompiled source",
}) {
    const limited = code.slice(0, 131072).split("\n").slice(0, 2000).join("\n");
    let line = 1;
    return (
        <pre className="static-code text-break" aria-label={label}>
            {limited.length < code.length && (
                <span className="text-warning-emphasis">
                    Source display truncated to 2000 lines / 128 KiB.{"\n"}
                </span>
            )}
            <code>
                <span className="static-line" aria-hidden="true">
                    {line}
                </span>
                {tokenize(limited, language).map((token, i) => (
                    <span key={i} className={`syntax-${token.kind}`}>
                        {token.text.split("\n").map((part, j) => (
                            <span key={j}>
                                {j > 0 && (
                                    <>
                                        {"\n"}
                                        <span
                                            className="static-line"
                                            aria-hidden="true"
                                        >
                                            {++line}
                                        </span>
                                    </>
                                )}
                                {part}
                            </span>
                        ))}
                    </span>
                ))}
            </code>
        </pre>
    );
}
export function GenericBlock({ value, depth = 0 }) {
    const [limit, setLimit] = useState(30);
    if (value == null || typeof value !== "object")
        return (
            <span className="text-break font-monospace">
                {String(value ?? "–").slice(0, 8192)}
            </span>
        );
    if (depth > 8) return <span>Nested data limit reached</span>;
    const entries = Object.entries(value);
    return (
        <div className="ps-2 border-start">
            {entries.slice(0, limit).map(([key, item]) => (
                <div key={key} className="text-break small mb-1">
                    {typeof item === "object" && item !== null ? (
                        <details>
                            <summary>
                                {key} ({Object.keys(item).length})
                            </summary>
                            <GenericBlock value={item} depth={depth + 1} />
                        </details>
                    ) : (
                        <>
                            <strong>{key}: </strong>
                            <GenericBlock value={item} depth={depth + 1} />
                        </>
                    )}
                </div>
            ))}
            {entries.length > limit && (
                <button
                    className="btn btn-sm btn-outline-secondary"
                    onClick={() => setLimit(limit + 30)}
                >
                    Show more fields
                </button>
            )}
        </div>
    );
}
export function SourceViewer({ source }) {
    const [layer, setLayer] = useState(0);
    if (!source) return null;
    const layers = [
        { ...source, method: "Original source" },
        ...(source.layers || []).slice(0, 30),
    ];
    const current = layers[layer] || layers[0];
    return (
        <section aria-label="Script source">
            <nav className="nav nav-tabs" aria-label="Decoded source layers">
                {layers.map((entry, i) => (
                    <button
                        key={i}
                        className={`nav-link ${i === layer ? "active" : ""}`}
                        onClick={() => setLayer(i)}
                    >
                        {entry.method || `Layer ${i}`}
                    </button>
                ))}
            </nav>
            <p className="small">
                {current.language}
                {current.truncated || source.truncated
                    ? " · Truncated source"
                    : ""}
            </p>
            <SourceCode
                code={current.text}
                language={current.language}
                label="Script source text"
            />
        </section>
    );
}
// Callers on the left, the current function in the middle, callees on the right (like a disassembler's
// proximity view); external calls are listed by address only.
export function XrefGraph({ current, byAddress, onSelect }) {
    if (!current) return null;
    const callers = (current.callers || []).slice(0, 12);
    const callees = (current.calls || []).slice(0, 12);
    const rows = Math.max(callers.length, callees.length, 1);
    const height = Math.max(90, rows * 34 + 20);
    const node = (address, x, y, key) => {
        const f = byAddress.get(address);
        const name = f?.name || address;
        return (
            <g
                key={key}
                role={f ? "button" : undefined}
                tabIndex={f ? 0 : undefined}
                aria-label={f ? `Open ${name}` : `External ${address}`}
                className={`code-graph-node ${f ? "is-internal" : "is-external"}`}
                onClick={() => f && onSelect(f)}
                onKeyDown={(e) => {
                    if (f && (e.key === "Enter" || e.key === " ")) {
                        e.preventDefault();
                        onSelect(f);
                    }
                }}
            >
                <rect x={x - 85} y={y - 13} width={170} height={26} rx={4} />
                <text x={x} y={y + 4} textAnchor="middle">
                    {String(name).slice(0, 24)}
                </text>
                <title>
                    {name} {address}
                </title>
            </g>
        );
    };
    const mid = height / 2;
    const at = (i, n) => (height - n * 34) / 2 + 17 + i * 34;
    return (
        <svg
            className="code-graph"
            role="img"
            aria-label={`Calls around ${current.name}`}
            viewBox={`0 0 640 ${height}`}
        >
            {callers.map((a, i) => (
                <line
                    key={`l-${a}-${i}`}
                    x1={185}
                    y1={at(i, callers.length)}
                    x2={235}
                    y2={mid}
                />
            ))}
            {callees.map((a, i) => (
                <line
                    key={`r-${a}-${i}`}
                    x1={405}
                    y1={mid}
                    x2={455}
                    y2={at(i, callees.length)}
                />
            ))}
            {callers.map((a, i) =>
                node(a, 100, at(i, callers.length), `c-${a}-${i}`),
            )}
            <g className="code-graph-node is-current">
                <rect x={235} y={mid - 15} width={170} height={30} rx={4} />
                <text x={320} y={mid + 4} textAnchor="middle">
                    {String(current.name).slice(0, 24)}
                </text>
            </g>
            {callees.map((a, i) =>
                node(a, 540, at(i, callees.length), `e-${a}-${i}`),
            )}
        </svg>
    );
}

const SORTS = {
    interest: (a, b) =>
        Number((b.reasons || []).some((r) => /entry|export/i.test(r))) -
            Number((a.reasons || []).some((r) => /entry|export/i.test(r))) ||
        (b.capa?.length || 0) - (a.capa?.length || 0) ||
        (b.size || 0) - (a.size || 0),
    address: (a, b) =>
        Number.parseInt(a.address, 16) - Number.parseInt(b.address, 16),
    size: (a, b) => (b.size || 0) - (a.size || 0),
    name: (a, b) => String(a.name).localeCompare(String(b.name)),
};
const MAX_TABS = 12;
const LIST_LIMIT = 400;

function Disassembly({ rows = [] }) {
    if (!rows.length)
        return (
            <p className="p-2">Disassembly not reported for this function.</p>
        );
    return (
        <pre className="static-code code-asm" aria-label="Disassembly">
            {rows.slice(0, 2000).map((row, i) => {
                const [mnemonic, ...rest] = String(row.t || "").split(" ");
                return (
                    <div key={i} className="code-asm-row">
                        <span className="syntax-number">{row.a}</span>
                        <span className="code-asm-bytes">{row.b}</span>
                        <span>
                            <span
                                className={
                                    /^(call|jmp|j[a-z]+|ret)$/i.test(mnemonic)
                                        ? "syntax-keyword"
                                        : ""
                                }
                            >
                                {mnemonic}
                            </span>{" "}
                            {rest.join(" ")}
                        </span>
                    </div>
                );
            })}
        </pre>
    );
}

export function CodeExplorer({ deep, format, source }) {
    const [query, setQuery] = useState(""),
        [sortBy, setSortBy] = useState("interest"),
        [pinned, setPinned] = useState(null),
        [tabs, setTabs] = useState(null),
        [view, setView] = useState("c"),
        [message, setMessage] = useState("");
    const ghidra = deep?.ghidra,
        all = ghidra?.functions || [];
    const byAddress = new Map(all.map((f) => [f.address, f]));
    if (source) return <SourceViewer source={source} />;
    if (!all.length)
        return (
            <section aria-label="Code">
                <h6>Decompiled code</h6>
                <p>
                    {!["pe", "elf"].includes(format)
                        ? "Decompilation is available only for PE and ELF files."
                        : !deep
                          ? "Deep pass not run yet. Code appears when decompilation finishes."
                          : "Decompiler is off or did not produce a result for this analysis."}
                </p>
            </section>
        );
    const funcs = all
        .filter((f) =>
            `${f.name} ${f.address} ${(f.capa || []).join(" ")}`
                .toLowerCase()
                .includes(query.toLowerCase()),
        )
        .sort(SORTS[sortBy]);
    // Open tabs: the first function until the analyst opens or closes one.
    const openTabs = tabs ?? [all[0].address];
    const closedAll = tabs !== null && !tabs.length && !pinned;
    // Nothing picked yet: follow the search, so typing jumps to the first match.
    const current = closedAll
        ? null
        : (pinned && byAddress.get(pinned)) || funcs[0] || null;
    const open = (f) => {
        setPinned(f.address);
        setTabs(
            openTabs.includes(f.address)
                ? openTabs
                : [...openTabs, f.address].slice(-MAX_TABS),
        );
    };
    const close = (address) => {
        const index = openTabs.indexOf(address);
        const rest = openTabs.filter((a) => a !== address);
        setTabs(rest);
        if (!current || current.address === address)
            setPinned(rest[Math.min(index, rest.length - 1)] ?? null);
    };
    const copy = async () => {
        try {
            await navigator.clipboard.writeText(
                view === "asm"
                    ? (current.asm || [])
                          .map((row) => `${row.a}  ${row.b}  ${row.t}`)
                          .join("\n")
                    : current.c,
            );
            setMessage("Copied code");
        } catch {
            setMessage("Copy unavailable; select the source manually.");
        }
    };
    const xrefs = (kind) =>
        (current?.[kind] || []).slice(0, 200).map((address) => {
            const target = byAddress.get(address);
            return (
                <li key={address}>
                    {target ? (
                        <button
                            type="button"
                            className="btn btn-sm btn-inline-link p-0 text-start"
                            onClick={() => open(target)}
                        >
                            {target.name}
                        </button>
                    ) : (
                        <span className="text-muted">external</span>
                    )}{" "}
                    <span className="font-monospace small">{address}</span>
                </li>
            );
        });
    return (
        <section aria-label="Code">
            <p className="small text-muted">
                Ghidra {ghidra.version} · {ghidra.language} ·{" "}
                {ghidra.decompiled} decompiled / {ghidra.functions_total}{" "}
                functions
            </p>
            <div className="code-ide">
                <aside
                    className="code-pane code-functions"
                    aria-label="Functions"
                >
                    <div className="code-pane-head">
                        <label className="w-100 small">
                            Search functions
                            <input
                                className="form-control form-control-sm"
                                value={query}
                                onChange={(e) => setQuery(e.target.value)}
                            />
                        </label>
                        <label className="w-100 small mt-1">
                            Sort
                            <select
                                className="form-select form-select-sm"
                                value={sortBy}
                                onChange={(e) => setSortBy(e.target.value)}
                            >
                                <option value="interest">
                                    Most interesting
                                </option>
                                <option value="address">Address</option>
                                <option value="size">Size</option>
                                <option value="name">Name</option>
                            </select>
                        </label>
                    </div>
                    <ul className="code-function-list">
                        {funcs.slice(0, LIST_LIMIT).map((f) => (
                            <li key={f.address}>
                                <button
                                    type="button"
                                    aria-pressed={current === f}
                                    className={
                                        current === f ? "is-current" : ""
                                    }
                                    onClick={() => open(f)}
                                    title={(f.reasons || []).join(" · ")}
                                >
                                    <span className="code-fn-name">
                                        {f.name}
                                    </span>
                                    <span className="code-fn-meta">
                                        {f.address} · {f.size ?? "?"} B
                                        {(f.reasons || []).some((r) =>
                                            /entry|export/i.test(r),
                                        ) ? (
                                            <span className="code-tag">
                                                entry
                                            </span>
                                        ) : null}
                                        {f.capa?.length ? (
                                            <span className="code-tag is-capa">
                                                capa {f.capa.length}
                                            </span>
                                        ) : null}
                                        {f.error ? (
                                            <span className="code-tag is-error">
                                                error
                                            </span>
                                        ) : null}
                                    </span>
                                </button>
                            </li>
                        ))}
                    </ul>
                    {funcs.length > LIST_LIMIT ? (
                        <p className="small text-muted px-2">
                            {funcs.length - LIST_LIMIT} more: refine the search.
                        </p>
                    ) : null}
                    {!funcs.length ? (
                        <p className="small px-2">No functions match.</p>
                    ) : null}
                </aside>
                <div className="code-pane code-main">
                    <div
                        className="code-tabs"
                        role="tablist"
                        aria-label="Open functions"
                    >
                        {openTabs.map((address) => {
                            const f = byAddress.get(address);
                            if (!f) return null;
                            const active = current?.address === address;
                            return (
                                <div
                                    key={address}
                                    className={`code-tab ${active ? "is-active" : ""}`}
                                    onAuxClick={(e) => {
                                        if (e.button === 1) close(address);
                                    }}
                                >
                                    <button
                                        type="button"
                                        role="tab"
                                        aria-selected={active}
                                        onClick={() => open(f)}
                                        title={`${f.name} ${f.address}`}
                                    >
                                        {f.name}
                                    </button>
                                    <button
                                        type="button"
                                        className="code-tab-close"
                                        aria-label={`Close ${f.name}`}
                                        onClick={() => close(address)}
                                    >
                                        ×
                                    </button>
                                </div>
                            );
                        })}
                        {openTabs.length > 1 ? (
                            <span className="code-tab-actions">
                                <button
                                    type="button"
                                    className="btn btn-sm btn-link"
                                    onClick={() => {
                                        if (current) {
                                            setTabs([current.address]);
                                            setPinned(current.address);
                                        }
                                    }}
                                >
                                    Close others
                                </button>
                                <button
                                    type="button"
                                    className="btn btn-sm btn-link"
                                    onClick={() => {
                                        setTabs([]);
                                        setPinned(null);
                                    }}
                                >
                                    Close all
                                </button>
                            </span>
                        ) : null}
                    </div>
                    {current ? (
                        <>
                            <div className="code-toolbar">
                                <h6 className="text-break m-0">
                                    {current.name}{" "}
                                    <span className="font-monospace small text-muted">
                                        {current.address} ·{" "}
                                        {current.size ?? "?"} bytes
                                    </span>
                                </h6>
                                <div
                                    className="chimera-segmented ms-auto"
                                    role="group"
                                    aria-label="Code view"
                                >
                                    {[
                                        ["c", "Pseudocode"],
                                        ["asm", "Disassembly"],
                                        ["split", "Split"],
                                    ].map(([id, text]) => (
                                        <button
                                            key={id}
                                            type="button"
                                            aria-pressed={view === id}
                                            onClick={() => setView(id)}
                                        >
                                            {text}
                                        </button>
                                    ))}
                                </div>
                                <button
                                    type="button"
                                    className="btn btn-sm btn-outline-secondary"
                                    disabled={!current.c && view !== "asm"}
                                    onClick={copy}
                                >
                                    Copy code
                                </button>
                            </div>
                            <span role="status" className="small">
                                {message}
                            </span>
                            {current.truncated && (
                                <p className="text-warning-emphasis small mb-1">
                                    Truncated: only part of this function is
                                    shown.
                                </p>
                            )}
                            {current.error && (
                                <p className="text-danger small mb-1">
                                    Decompilation error: {current.error}
                                </p>
                            )}
                            <div className={`code-view is-${view}`}>
                                {view !== "asm" ? (
                                    current.c && current.c !== "None" ? (
                                        <SourceCode code={current.c} />
                                    ) : (
                                        <p className="p-2">
                                            No source available.
                                        </p>
                                    )
                                ) : null}
                                {view !== "c" ? (
                                    <Disassembly rows={current.asm} />
                                ) : null}
                            </div>
                        </>
                    ) : (
                        <p className="p-3 text-muted">
                            No function open. Pick one from the list.
                        </p>
                    )}
                </div>
                <aside
                    className="code-pane code-xrefs"
                    aria-label="Cross-references"
                >
                    {current ? (
                        <>
                            <h6>Called by ({current.callers?.length || 0})</h6>
                            {current.callers?.length ? (
                                <ul className="code-xref-list">
                                    {xrefs("callers")}
                                </ul>
                            ) : (
                                <p className="small text-muted">
                                    No callers reported.
                                </p>
                            )}
                            <h6>Calls ({current.calls?.length || 0})</h6>
                            {current.calls?.length ? (
                                <ul className="code-xref-list">
                                    {xrefs("calls")}
                                </ul>
                            ) : (
                                <p className="small text-muted">
                                    No calls reported.
                                </p>
                            )}
                            <h6>capa in this function</h6>
                            {current.capa?.length ? (
                                <ul className="small ps-3">
                                    {current.capa.map((c) => (
                                        <li key={c}>{c}</li>
                                    ))}
                                </ul>
                            ) : (
                                <p className="small text-muted">None.</p>
                            )}
                            <h6>Why it is listed</h6>
                            <p className="small">
                                {(current.reasons || []).join(" · ") || "–"}
                            </p>
                        </>
                    ) : null}
                </aside>
            </div>
            {current && (current.callers?.length || current.calls?.length) ? (
                <details open className="mt-2">
                    <summary>Call graph around {current.name}</summary>
                    <XrefGraph
                        current={current}
                        byAddress={byAddress}
                        onSelect={open}
                    />
                </details>
            ) : null}
        </section>
    );
}
