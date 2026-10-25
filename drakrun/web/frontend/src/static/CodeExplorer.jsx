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
export function CallGraph({ functions, current, onSelect }) {
    const visible = functions.slice(0, 30);
    const positions = new Map(
        visible.map((f, i) => [
            f.address,
            { x: 110 + (i % 3) * 210, y: 30 + Math.floor(i / 3) * 70 },
        ]),
    );
    return (
        <details>
            <summary>Call graph ({visible.length} functions)</summary>
            <svg
                role="img"
                aria-label="Function call graph"
                viewBox={`0 0 650 ${Math.max(100, Math.ceil(visible.length / 3) * 70)}`}
                style={{ width: "100%", maxHeight: 400 }}
            >
                {visible.flatMap((f) =>
                    (f.calls || [])
                        .filter((a) => positions.has(a))
                        .slice(0, 100)
                        .map((a, i) => (
                            <line
                                key={`${f.address}-${i}`}
                                x1={positions.get(f.address).x}
                                y1={positions.get(f.address).y}
                                x2={positions.get(a).x}
                                y2={positions.get(a).y}
                                stroke="currentColor"
                                opacity=".35"
                            />
                        )),
                )}
                {visible.map((f) => {
                    const { x, y } = positions.get(f.address);
                    return (
                        <g
                            key={f.address}
                            role="button"
                            tabIndex={0}
                            aria-label={`Navigate to ${f.name}`}
                            onClick={() => onSelect(f)}
                            onKeyDown={(e) => {
                                if (e.key === "Enter" || e.key === " ") {
                                    e.preventDefault();
                                    onSelect(f);
                                }
                            }}
                        >
                            <rect
                                x={x - 95}
                                y={y - 15}
                                width={190}
                                height={32}
                                rx={4}
                                fill={
                                    current?.address === f.address
                                        ? "#446baf"
                                        : "#45505c"
                                }
                            />
                            <text
                                x={x}
                                y={y + 5}
                                textAnchor="middle"
                                fill="white"
                                fontSize={11}
                            >
                                {f.name?.slice(0, 26)}
                            </text>
                            <title>
                                {f.name} {f.address}
                            </title>
                        </g>
                    );
                })}
            </svg>
            {functions.length > 30 && (
                <p className="small">
                    Graph shows the first 30 decompiled functions.
                </p>
            )}
        </details>
    );
}
export function CodeExplorer({ deep, format, source }) {
    const [query, setQuery] = useState(""),
        [selected, setSelected] = useState(null),
        [opened, setOpened] = useState([]),
        [asm, setAsm] = useState(false),
        [message, setMessage] = useState("");
    const ghidra = deep?.ghidra,
        all = ghidra?.functions || [];
    const funcs = all.filter((f) =>
        `${f.name} ${f.address} ${(f.capa || []).join(" ")}`
            .toLowerCase()
            .includes(query.toLowerCase()),
    );
    const current = funcs.find((f) => f.address === selected) || funcs[0];
    const choose = (f) => {
        setQuery("");
        setSelected(f.address);
        setOpened((old) => [...new Set([...old, f.address])].slice(-20));
    };
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
    const groups = [
        [
            "Entry / exports",
            funcs.filter((f) =>
                (f.reasons || []).some((r) => /entry|export/i.test(r)),
            ),
        ],
        ["capa-linked", funcs.filter((f) => f.capa?.length)],
        [
            "Largest / other functions",
            [...funcs].sort((a, b) => (b.size || 0) - (a.size || 0)),
        ],
    ];
    return (
        <section aria-label="Code">
            <p className="small text-muted">
                Ghidra {ghidra.version} · {ghidra.language} ·{" "}
                {ghidra.decompiled} decompiled / {ghidra.functions_total}{" "}
                functions
            </p>
            <CallGraph functions={all} current={current} onSelect={choose} />
            <div className="static-code-layout">
                <aside>
                    <label className="w-100">
                        Search functions
                        <input
                            className="form-control form-control-sm mb-2"
                            value={query}
                            onChange={(e) => setQuery(e.target.value)}
                        />
                    </label>
                    {groups.map(([name, list]) => (
                        <details key={name} open>
                            <summary>
                                {name} ({list.length})
                            </summary>
                            {list.slice(0, 100).map((f) => (
                                <button
                                    key={f.address}
                                    aria-pressed={current === f}
                                    className="btn btn-sm text-start w-100 border text-break mb-1"
                                    onClick={() => choose(f)}
                                >
                                    <strong>{f.name}</strong>
                                    <div className="font-monospace small">
                                        {f.address} · {f.size} bytes
                                    </div>
                                    <div className="small">
                                        {(f.reasons || []).join(" · ")}
                                    </div>
                                </button>
                            ))}
                        </details>
                    ))}
                </aside>
                <div className="static-source">
                    <nav className="nav nav-tabs" aria-label="Open functions">
                        {[
                            ...new Set([
                                ...(all[0] ? [all[0].address] : []),
                                ...opened,
                            ]),
                        ].map((address) => {
                            const f = all.find(
                                (item) => item.address === address,
                            );
                            return (
                                f && (
                                    <button
                                        className={`nav-link ${current === f ? "active" : ""}`}
                                        key={address}
                                        onClick={() => choose(f)}
                                    >
                                        {f.name}
                                    </button>
                                )
                            );
                        })}
                    </nav>
                    {current ? (
                        <>
                            <div className="d-flex gap-2 align-items-center my-2">
                                <h6 className="text-break">{current.name}</h6>
                                <label className="ms-auto">
                                    <input
                                        type="checkbox"
                                        checked={asm}
                                        onChange={(e) =>
                                            setAsm(e.target.checked)
                                        }
                                    />{" "}
                                    Disassembly
                                </label>
                                <button
                                    className="btn btn-sm btn-outline-secondary"
                                    disabled={!current.c && !asm}
                                    onClick={async () => {
                                        try {
                                            await navigator.clipboard.writeText(
                                                asm
                                                    ? (current.asm || [])
                                                          .map(
                                                              (row) =>
                                                                  `${row.a}  ${row.b}  ${row.t}`,
                                                          )
                                                          .join("\n")
                                                    : current.c,
                                            );
                                            setMessage("Copied code");
                                        } catch {
                                            setMessage(
                                                "Copy unavailable; select the source manually.",
                                            );
                                        }
                                    }}
                                >
                                    Copy code
                                </button>
                            </div>
                            <span role="status">{message}</span>
                            {current.truncated && (
                                <p className="text-warning-emphasis">
                                    Truncated: only part of this function is
                                    shown.
                                </p>
                            )}
                            {current.error && (
                                <p className="text-danger">
                                    Decompilation error: {current.error}
                                </p>
                            )}
                            {["callers", "calls"].map((kind) => (
                                <div className="small mb-2" key={kind}>
                                    <strong>
                                        {kind === "calls"
                                            ? "Callees"
                                            : "Callers"}
                                        :{" "}
                                    </strong>
                                    {(current[kind] || [])
                                        .slice(0, 100)
                                        .map((address) => {
                                            const target = all.find(
                                                (f) => f.address === address,
                                            );
                                            return target ? (
                                                <button
                                                    className="btn btn-sm btn-inline-link"
                                                    key={address}
                                                    onClick={() =>
                                                        choose(target)
                                                    }
                                                >
                                                    {target.name}
                                                </button>
                                            ) : (
                                                <span
                                                    className="font-monospace me-2"
                                                    key={address}
                                                >
                                                    {address}
                                                </span>
                                            );
                                        })}
                                </div>
                            ))}
                            {asm ? (
                                current.asm?.length ? (
                                    <pre className="static-code text-break">
                                        {current.asm
                                            .slice(0, 300)
                                            .map((row, i) => (
                                                <div key={i}>
                                                    <span className="syntax-number">
                                                        {row.a}
                                                    </span>{" "}
                                                    <span className="text-muted">
                                                        {row.b}
                                                    </span>{" "}
                                                    {row.t}
                                                </div>
                                            ))}
                                    </pre>
                                ) : (
                                    <p>
                                        Disassembly not reported for this
                                        function.
                                    </p>
                                )
                            ) : current.c ? (
                                <SourceCode code={current.c} />
                            ) : (
                                <p>No source available.</p>
                            )}
                        </>
                    ) : (
                        <p>No functions match.</p>
                    )}
                </div>
            </div>
        </section>
    );
}
