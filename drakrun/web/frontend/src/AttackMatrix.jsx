import { useMemo, useState } from "react";
import ATTACK from "./data/attack.json";

// Where an ATT&CK mapping comes from. "dynamic" is behaviour of the sample's own process tree seen at run time;
// "static" and "capa" are capabilities found in the file (code that could do it, not proof that it ran); "system"
// is behaviour of other guest processes (Windows itself, services) during the run.
export const ATTACK_SOURCES = {
    dynamic: {
        label: "Observed",
        note: "seen at run time in the sample's process tree",
        strength: "observed",
    },
    capa: {
        label: "Code (capa)",
        note: "code in the file that implements it",
        strength: "potential",
    },
    static: {
        label: "Static",
        note: "found in the file's content or structure",
        strength: "potential",
    },
    system: {
        label: "Other process",
        note: "other guest processes during the run",
        strength: "system",
    },
};

const TECHNIQUE = /\[(T\d{4}(?:\.\d{3})?)\]/;
const UNMAPPED = "Unmapped";

export function techniqueName(id) {
    const entry = ATTACK.techniques[id];
    if (!entry) return id;
    const parent = entry.parent ? ATTACK.techniques[entry.parent] : null;
    return parent ? `${parent.name}: ${entry.name}` : entry.name;
}

export const attackUrl = (id) =>
    `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;

// Seqids of the sample's process tree: the started process and everything below it.
export function sampleScope(summary) {
    const processes = summary?.processes || {};
    const root = summary?.startup?.process;
    const scope = new Set();
    if (root == null) return scope;
    const children = {};
    for (const [seqid, process] of Object.entries(processes)) {
        const parent = process?.parent_seqid;
        if (parent != null) (children[parent] ||= []).push(Number(seqid));
    }
    const stack = [Number(root)];
    while (stack.length) {
        const seqid = stack.pop();
        if (scope.has(seqid)) continue;
        scope.add(seqid);
        stack.push(...(children[seqid] || []));
    }
    return scope;
}

// report.json ttps -> matrix entries; entries outside the sample's tree become "system".
export function entriesFromTtps(ttps = [], scope = new Set()) {
    const out = [];
    for (const ttp of Array.isArray(ttps) ? ttps : []) {
        const seqids = ttp.process_seqids || [];
        const inScope = !scope.size || seqids.some((s) => scope.has(Number(s)));
        for (const text of ttp["att&ck"] || []) {
            const match = TECHNIQUE.exec(text);
            if (!match) continue;
            out.push({
                technique: match[1],
                name: ttp.name,
                source: inScope ? "dynamic" : "system",
                tactic: text.split("::")[0],
            });
        }
    }
    return out;
}

const strengthOf = (cell) =>
    cell.sources.has("dynamic")
        ? "observed"
        : cell.sources.has("static") || cell.sources.has("capa")
          ? "potential"
          : "system";
const strengthRank = (cell) =>
    ({ observed: 0, potential: 1, system: 2 })[strengthOf(cell)];

function group(entries) {
    const columns = new Map();
    const add = (tactic, base, entry) => {
        if (!columns.has(tactic)) columns.set(tactic, new Map());
        const cells = columns.get(tactic);
        if (!cells.has(base))
            cells.set(base, {
                id: base,
                subs: new Set(),
                behaviours: new Map(),
                sources: new Set(),
            });
        const cell = cells.get(base);
        if (entry.technique !== base) cell.subs.add(entry.technique);
        cell.sources.add(entry.source);
        const key = `${entry.name || entry.technique}\u0000${entry.source}\u0000${entry.technique}`;
        if (!cell.behaviours.has(key))
            cell.behaviours.set(key, {
                name: entry.name || techniqueName(entry.technique),
                source: entry.source,
                technique: entry.technique,
            });
    };
    for (const entry of entries) {
        if (!entry?.technique) continue;
        const base = entry.technique.split(".")[0];
        const known =
            ATTACK.techniques[entry.technique] || ATTACK.techniques[base];
        const tactics = known?.tactics?.length
            ? known.tactics
            : ATTACK.tactics.includes(entry.tactic)
              ? [entry.tactic]
              : [UNMAPPED];
        for (const tactic of tactics) add(tactic, base, entry);
    }
    const order = [...ATTACK.tactics, UNMAPPED];
    return [...columns.entries()]
        .sort(([a], [b]) => order.indexOf(a) - order.indexOf(b))
        .map(([tactic, cells]) => ({
            tactic,
            cells: [...cells.values()].sort(
                (a, b) =>
                    strengthRank(a) - strengthRank(b) ||
                    b.behaviours.size - a.behaviours.size ||
                    a.id.localeCompare(b.id),
            ),
        }));
}

export function AttackMatrix({
    entries = [],
    systemEntries = [],
    compact = false,
}) {
    const [withSystem, setWithSystem] = useState(false);
    const [selected, setSelected] = useState(null);
    const shown = useMemo(
        () => (withSystem ? [...entries, ...systemEntries] : entries),
        [entries, systemEntries, withSystem],
    );
    const columns = useMemo(() => group(shown), [shown]);
    const techniqueCount = new Set(
        shown.map((e) => e.technique?.split(".")[0]).filter(Boolean),
    ).size;
    const selectedCell = selected
        ? columns
              .flatMap((c) =>
                  c.cells.map((cell) => ({ ...cell, tactic: c.tactic })),
              )
              .find((cell) => `${cell.tactic}/${cell.id}` === selected)
        : null;
    const systemCount = new Set(systemEntries.map((e) => e.technique)).size;
    return (
        <div className="attack-matrix">
            <div className="attack-legend small">
                <span>
                    <strong>{techniqueCount}</strong> technique
                    {techniqueCount === 1 ? "" : "s"} across{" "}
                    <strong>{columns.length}</strong> tactic
                    {columns.length === 1 ? "" : "s"}
                </span>
                <span className="attack-key is-observed">
                    Observed at run time
                </span>
                <span className="attack-key is-potential">
                    Capability in the file (static, capa)
                </span>
                {withSystem ? (
                    <span className="attack-key is-system">
                        Other guest processes
                    </span>
                ) : null}
                {systemCount ? (
                    <label className="form-check form-switch m-0 ms-auto">
                        <input
                            className="form-check-input"
                            type="checkbox"
                            role="switch"
                            checked={withSystem}
                            onChange={(e) => setWithSystem(e.target.checked)}
                        />
                        <span className="form-check-label">
                            Include other guest processes ({systemCount})
                        </span>
                    </label>
                ) : null}
            </div>
            {!columns.length ? (
                <p className="small text-muted mb-0">
                    No ATT&CK technique was mapped for the sample
                    {systemCount && !withSystem
                        ? " (other guest processes have some: use the switch above)"
                        : ""}
                    .
                </p>
            ) : (
                <div className="attack-scroll">
                    <div
                        className="attack-grid"
                        style={{
                            gridTemplateColumns: `repeat(${columns.length}, minmax(${compact ? 9.5 : 11}rem, 1fr))`,
                        }}
                    >
                        {columns.map(({ tactic, cells }) => (
                            <div
                                key={tactic}
                                className="attack-col"
                                role="group"
                                aria-label={tactic}
                            >
                                <div className="attack-tactic">
                                    <span>{tactic}</span>
                                    <span className="attack-tactic-count">
                                        {cells.length}
                                    </span>
                                </div>
                                {cells.map((cell) => {
                                    const key = `${tactic}/${cell.id}`;
                                    return (
                                        <button
                                            key={cell.id}
                                            type="button"
                                            className={`attack-cell is-${strengthOf(cell)}`}
                                            aria-pressed={selected === key}
                                            aria-label={`${cell.id} ${techniqueName(cell.id)}: ${cell.behaviours.size} behaviour(s)`}
                                            onClick={() =>
                                                setSelected(
                                                    selected === key
                                                        ? null
                                                        : key,
                                                )
                                            }
                                        >
                                            <span className="attack-id">
                                                {cell.id}
                                                <span className="attack-count">
                                                    {cell.behaviours.size}
                                                </span>
                                            </span>
                                            <span className="attack-name">
                                                {ATTACK.techniques[cell.id]
                                                    ?.name || cell.id}
                                            </span>
                                            {[...cell.subs]
                                                .sort()
                                                .map((sub) => (
                                                    <span
                                                        key={sub}
                                                        className="attack-sub"
                                                    >
                                                        .{sub.split(".")[1]}{" "}
                                                        {ATTACK.techniques[sub]
                                                            ?.name || ""}
                                                    </span>
                                                ))}
                                        </button>
                                    );
                                })}
                            </div>
                        ))}
                    </div>
                </div>
            )}
            {selectedCell ? (
                <div className="attack-detail" aria-live="polite">
                    <div className="d-flex flex-wrap align-items-baseline gap-2 mb-2">
                        <strong>
                            {selectedCell.id} {techniqueName(selectedCell.id)}
                        </strong>
                        <span className="small text-muted">
                            {selectedCell.tactic}
                        </span>
                        <a
                            className="small ms-auto"
                            href={attackUrl(selectedCell.id)}
                            target="_blank"
                            rel="noopener noreferrer"
                        >
                            ATT&CK page
                        </a>
                    </div>
                    <ul className="mb-0 small">
                        {[...selectedCell.behaviours.values()].map((b) => (
                            <li key={`${b.name}/${b.source}/${b.technique}`}>
                                {b.name}{" "}
                                <span
                                    className={`attack-key is-${ATTACK_SOURCES[b.source]?.strength || "system"}`}
                                    title={ATTACK_SOURCES[b.source]?.note}
                                >
                                    {ATTACK_SOURCES[b.source]?.label ||
                                        b.source}
                                </span>
                                {b.technique !== selectedCell.id ? (
                                    <span className="text-muted ms-1">
                                        {b.technique}{" "}
                                        {ATTACK.techniques[b.technique]?.name}
                                    </span>
                                ) : null}
                            </li>
                        ))}
                    </ul>
                </div>
            ) : null}
        </div>
    );
}
