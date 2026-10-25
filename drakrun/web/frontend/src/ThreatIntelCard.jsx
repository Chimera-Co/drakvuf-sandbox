import { useEffect, useMemo, useState } from "react";
import {
    getIntel,
    getIntelProviders,
    recheckIntel,
    refreshIntel,
} from "./intelApi.js";
import { Pagination, useLocalPagination } from "./Pagination.jsx";

export const PROVIDER_LABEL = {
    virustotal: "VirusTotal",
    malwarebazaar: "MalwareBazaar",
    threatfox: "ThreatFox",
    urlhaus: "URLhaus",
    otx: "AlienVault OTX",
    abuseipdb: "AbuseIPDB",
    greynoise: "GreyNoise",
    hashlookup: "CIRCL hashlookup",
    hybridanalysis: "Hybrid Analysis",
    urlscan: "urlscan.io",
};
const ORIGIN_LABEL = {
    sample: "The sample",
    dynamic: "Sample's processes",
    memory: "Sample's memory dumps",
    unattributed: "Unattributed traffic",
    static: "Strings in the file",
};
const HASH_TYPES = new Set(["sha256", "sha1", "md5"]);
const VERDICT_RANK = {
    malicious: 0,
    suspicious: 1,
    harmless: 3,
    unknown: 2,
};
const label = (id) => PROVIDER_LABEL[id] || id;
const safeLink = (url) =>
    typeof url === "string" && /^https:\/\//.test(url) ? url : null;

export function formatWhen(value) {
    if (value == null || value === "") return null;
    const date =
        typeof value === "number"
            ? new Date(value * 1000)
            : new Date(String(value).replace(" ", "T"));
    if (Number.isNaN(date.getTime())) return String(value);
    return date.toISOString().slice(0, 10);
}

// One provider's answer for one observable, in words an analyst reads at a glance.
export function outcome(row) {
    const d = row.details || {};
    if (row.status === "not_found")
        return {
            tone: "none",
            text:
                row.provider === "greynoise"
                    ? "Not seen scanning"
                    : row.provider === "hashlookup"
                      ? "Not a known file"
                      : "Not listed",
        };
    if (row.status === "rate_limited")
        return { tone: "warn", text: "Rate limited" };
    if (row.status === "offline")
        return { tone: "warn", text: "Provider unreachable" };
    if (row.status !== "ok")
        return {
            tone: "warn",
            text: d.reason === "bad key" ? "Key rejected" : "Lookup failed",
        };
    const ratio = row.detections
        ? ` ${row.detections.malicious || 0}/${row.detections.total || 0}`
        : "";
    if (row.verdict === "malicious")
        return {
            tone: "bad",
            text: `Malicious${ratio}${row.family ? ` · ${row.family}` : ""}`,
        };
    if (row.verdict === "suspicious")
        return {
            tone: "warn",
            text: `Suspicious${ratio}${row.family ? ` · ${row.family}` : ""}`,
        };
    if (row.verdict === "harmless")
        return {
            tone: "good",
            text:
                row.provider === "hashlookup"
                    ? `Known file${d.ProductName ? ` · ${d.ProductName}` : ""}`
                    : row.provider === "greynoise" && d.riot
                      ? `Common service${d.name ? ` · ${d.name}` : ""}`
                      : `Harmless${ratio}`,
        };
    if (row.provider === "urlscan")
        return {
            tone: "none",
            text: `Seen in ${d.count ?? "?"} scans, ${d.malicious_count ?? 0} malicious`,
        };
    if (row.provider === "otx")
        return { tone: "none", text: `${d.pulse_count ?? 0} pulses` };
    return { tone: "none", text: ratio ? `No verdict${ratio}` : "Seen" };
}

function Outcome({ row }) {
    const { tone, text } = outcome(row);
    const link = safeLink(row.permalink);
    return (
        <span className={`intel-outcome is-${tone}`}>
            <span className="intel-provider">{label(row.provider)}</span>
            {link ? (
                <a href={link} target="_blank" rel="noopener noreferrer">
                    {text}
                </a>
            ) : (
                <span>{text}</span>
            )}
        </span>
    );
}

function worst(rows) {
    return rows.reduce(
        (best, row) =>
            row.status === "ok" &&
            (VERDICT_RANK[row.verdict] ?? 2) < (VERDICT_RANK[best] ?? 2)
                ? row.verdict
                : best,
        "unknown",
    );
}

function VerdictPill({ verdict }) {
    const text =
        {
            malicious: "Malicious",
            suspicious: "Suspicious",
            harmless: "Known good",
        }[verdict] || "No verdict";
    return <span className={`intel-pill is-${verdict}`}>{text}</span>;
}

function DetectionMeter({ detections }) {
    const total = detections?.total || 0;
    const bad = detections?.malicious || 0;
    const sus = detections?.suspicious || 0;
    if (!total) return null;
    return (
        <div className="intel-meter" aria-label={`${bad} of ${total} engines`}>
            <div className="intel-meter-figure">
                <strong>{bad}</strong>
                <span>/ {total} engines</span>
            </div>
            <div className="intel-meter-bar">
                <span
                    className="is-bad"
                    style={{ width: `${(bad / total) * 100}%` }}
                />
                <span
                    className="is-warn"
                    style={{ width: `${(sus / total) * 100}%` }}
                />
            </div>
        </div>
    );
}

function Facts({ items }) {
    const shown = items.filter(
        ([, v]) => v != null && v !== "" && !(Array.isArray(v) && !v.length),
    );
    if (!shown.length) return null;
    return (
        <dl className="intel-facts">
            {shown.map(([k, v]) => (
                <div key={k}>
                    <dt>{k}</dt>
                    <dd>{Array.isArray(v) ? v.join(", ") : String(v)}</dd>
                </div>
            ))}
        </dl>
    );
}

// The full VirusTotal record: engines, threat names, file or network facts, crowdsourced rules, sandboxes.
export function VirusTotalDetail({ row }) {
    const d = row.details || {};
    const file = d.file || {};
    const net = d.network || {};
    const threat = d.threat || {};
    const rules = d.rules || {};
    const link = safeLink(row.permalink);
    return (
        <div className="intel-vt">
            <div className="intel-vt-head">
                <DetectionMeter detections={row.detections} />
                <div className="intel-vt-title">
                    <VerdictPill verdict={row.verdict} />
                    {threat.label ? (
                        <strong className="ms-2">{threat.label}</strong>
                    ) : null}
                    <div className="small text-muted text-break">
                        {row.observable}
                    </div>
                </div>
                {link ? (
                    <a
                        className="btn btn-sm btn-outline-secondary ms-auto"
                        href={link}
                        target="_blank"
                        rel="noopener noreferrer"
                    >
                        Open in VirusTotal
                    </a>
                ) : null}
            </div>
            <Facts
                items={[
                    ["Threat category", threat.categories],
                    ["Family names", threat.names],
                    ["Name", file.meaningful_name],
                    ["Type", file.type],
                    ["Size", file.size != null ? `${file.size} bytes` : null],
                    [
                        "Signed",
                        file.signed == null
                            ? null
                            : file.signed
                              ? file.signer || "yes"
                              : "no",
                    ],
                    ["Times submitted", file.times_submitted],
                    ["First seen", formatWhen(row.first_seen)],
                    ["First seen in the wild", formatWhen(file.first_seen_itw)],
                    ["Last analysed", formatWhen(d.last_analysis_date)],
                    ["Reputation", d.reputation],
                    ["Categories", net.categories],
                    ["Registrar", net.registrar],
                    ["Created", formatWhen(net.created)],
                    ["Country", net.country],
                    [
                        "Network",
                        [
                            net.as_owner,
                            net.asn && `AS${net.asn}`,
                            net.network,
                        ].filter(Boolean),
                    ],
                    ["Tags", row.tags],
                    ["Other names", file.names],
                ]}
            />
            {d.engines?.length ? (
                <>
                    <h4 className="intel-subhead">
                        Engines that flagged it (
                        {d.engines_flagged ?? d.engines.length})
                    </h4>
                    <div className="intel-engines">
                        {d.engines.map((e) => (
                            <div key={e.engine} className={`is-${e.category}`}>
                                <span>{e.engine}</span>
                                <code>{e.result || e.category}</code>
                            </div>
                        ))}
                    </div>
                </>
            ) : null}
            {d.sandbox_verdicts?.length ? (
                <>
                    <h4 className="intel-subhead">Sandbox verdicts</h4>
                    <ul className="intel-list">
                        {d.sandbox_verdicts.map((s) => (
                            <li key={s.sandbox}>
                                {s.sandbox}: {s.category}
                                {s.families?.length
                                    ? ` (${s.families.join(", ")})`
                                    : ""}
                            </li>
                        ))}
                    </ul>
                </>
            ) : null}
            {[
                ["Crowdsourced YARA", rules.yara],
                ["Sigma", rules.sigma],
                ["IDS", rules.ids],
            ].map(([title, list]) =>
                list?.filter(Boolean).length ? (
                    <div key={title}>
                        <h4 className="intel-subhead">{title}</h4>
                        <ul className="intel-list">
                            {list.filter(Boolean).map((r) => (
                                <li key={r}>{r}</li>
                            ))}
                        </ul>
                    </div>
                ) : null,
            )}
        </div>
    );
}

function SampleReputation({ rows }) {
    if (!rows.length) return null;
    const vt = rows.find(
        (r) => r.provider === "virustotal" && r.status === "ok",
    );
    return (
        <section className="intel-section">
            <h3 className="intel-heading">Sample reputation</h3>
            <div className="intel-outcomes mb-2">
                {rows.map((row) => (
                    <Outcome key={row.provider} row={row} />
                ))}
            </div>
            {rows
                .filter(
                    (r) =>
                        r.status === "ok" &&
                        r.provider !== "virustotal" &&
                        (r.family || r.first_seen || r.tags?.length),
                )
                .map((r) => (
                    <div key={r.provider} className="small mb-1">
                        <strong>{label(r.provider)}:</strong>{" "}
                        {[
                            r.family,
                            ...(r.tags || []),
                            r.first_seen &&
                                `first seen ${formatWhen(r.first_seen)}`,
                        ]
                            .filter(Boolean)
                            .join(" · ")}
                    </div>
                ))}
            {vt ? <VirusTotalDetail row={vt} /> : null}
        </section>
    );
}

function NetworkIndicators({ rows }) {
    const [flaggedOnly, setFlaggedOnly] = useState(false);
    const [open, setOpen] = useState(null);
    const groups = useMemo(() => {
        const map = new Map();
        for (const row of rows) {
            const key = `${row.type}\u0000${row.observable}`;
            if (!map.has(key))
                map.set(key, {
                    key,
                    type: row.type,
                    observable: row.observable,
                    origin: row.origin,
                    rows: [],
                });
            map.get(key).rows.push(row);
        }
        return [...map.values()]
            .map((g) => ({ ...g, verdict: worst(g.rows) }))
            .sort(
                (a, b) =>
                    (VERDICT_RANK[a.verdict] ?? 2) -
                        (VERDICT_RANK[b.verdict] ?? 2) ||
                    a.observable.localeCompare(b.observable),
            );
    }, [rows]);
    const shown = flaggedOnly
        ? groups.filter((g) => ["malicious", "suspicious"].includes(g.verdict))
        : groups;
    const pager = useLocalPagination(shown.length, 10);
    if (!groups.length) return null;
    const flagged = groups.filter((g) =>
        ["malicious", "suspicious"].includes(g.verdict),
    ).length;
    return (
        <section className="intel-section">
            <div className="chimera-table-toolbar">
                <h3 className="intel-heading mb-0">
                    Network and string indicators{" "}
                    <span className="badge bg-secondary">{groups.length}</span>
                </h3>
                <label className="form-check form-switch m-0 small">
                    <input
                        className="form-check-input"
                        type="checkbox"
                        role="switch"
                        checked={flaggedOnly}
                        onChange={(e) => {
                            setFlaggedOnly(e.target.checked);
                            pager.setPage(1);
                        }}
                    />
                    <span className="form-check-label">
                        Only flagged ({flagged})
                    </span>
                </label>
            </div>
            <div className="chimera-table-scroll">
                <table
                    className="table table-sm chimera-data-table"
                    aria-label="Online lookups by indicator"
                >
                    <thead>
                        <tr>
                            <th scope="col">Indicator</th>
                            <th scope="col">Type</th>
                            <th scope="col">Where it came from</th>
                            <th scope="col">Verdict</th>
                            <th scope="col">Providers</th>
                        </tr>
                    </thead>
                    <tbody>
                        {pager.slice(shown).map((g) => {
                            const vt = g.rows.find(
                                (r) =>
                                    r.provider === "virustotal" &&
                                    r.status === "ok",
                            );
                            return [
                                <tr key={g.key}>
                                    <td className="cell-mono cell-long">
                                        {g.observable}
                                    </td>
                                    <td className="cell-short">{g.type}</td>
                                    <td className="cell-short">
                                        {ORIGIN_LABEL[g.origin] ||
                                            g.origin ||
                                            "–"}
                                    </td>
                                    <td className="cell-short">
                                        <VerdictPill verdict={g.verdict} />
                                    </td>
                                    <td className="cell-long">
                                        <div className="intel-outcomes">
                                            {g.rows.map((row) => (
                                                <Outcome
                                                    key={row.provider}
                                                    row={row}
                                                />
                                            ))}
                                            {vt ? (
                                                <button
                                                    type="button"
                                                    className="btn btn-sm btn-link p-0"
                                                    aria-expanded={
                                                        open === g.key
                                                    }
                                                    onClick={() =>
                                                        setOpen(
                                                            open === g.key
                                                                ? null
                                                                : g.key,
                                                        )
                                                    }
                                                >
                                                    {open === g.key
                                                        ? "Hide VirusTotal detail"
                                                        : "VirusTotal detail"}
                                                </button>
                                            ) : null}
                                        </div>
                                    </td>
                                </tr>,
                                vt && open === g.key ? (
                                    <tr key={`${g.key}-vt`}>
                                        <td colSpan={5}>
                                            <VirusTotalDetail row={vt} />
                                        </td>
                                    </tr>
                                ) : null,
                            ];
                        })}
                    </tbody>
                </table>
            </div>
            <Pagination
                pager={pager}
                label="Indicator pages"
                noun="indicators"
            />
        </section>
    );
}

function OfflineFeeds({ payload, onCopy }) {
    const feeds = payload.feeds || [];
    const matches = payload.matches || [];
    const dates = [...new Set(feeds.map((f) => formatWhen(f.fetched_at)))].join(
        ", ",
    );
    return (
        <section className="intel-section">
            <h3 className="intel-heading">
                Offline feeds{" "}
                <span className="badge bg-secondary">{matches.length}</span>
            </h3>
            <div className="d-flex flex-wrap gap-2 mb-2">
                {feeds.map((feed) => (
                    <span
                        key={feed.name}
                        className={`badge ${feed.stale ? "bg-warning text-dark" : "bg-success"}`}
                        title={`Fetched ${feed.fetched_at}; expires ${feed.expires_at}`}
                    >
                        {feed.name}: {feed.stale ? "stale" : "fresh"}
                    </span>
                ))}
                {(payload.failures || []).map((feed) => (
                    <span key={feed.name} className="badge bg-secondary">
                        {feed.name}: missing
                    </span>
                ))}
            </div>
            {!matches.length ? (
                <p className="small mb-1">
                    No match in the offline feeds (dated {dates || "unknown"}):
                    not a verdict of benign
                </p>
            ) : (
                <div className="chimera-table-scroll">
                    <table
                        className="table table-sm chimera-data-table"
                        aria-label="Offline feed matches"
                    >
                        <thead>
                            <tr>
                                {[
                                    "Indicator",
                                    "Type",
                                    "Where observed",
                                    "Feed",
                                    "Family / tags",
                                    "First / last seen",
                                    "Reference",
                                ].map((h) => (
                                    <th key={h} scope="col">
                                        {h}
                                    </th>
                                ))}
                            </tr>
                        </thead>
                        <tbody>
                            {matches.map((row, i) => (
                                <tr key={i}>
                                    <td className="font-monospace text-break cell-long">
                                        {row.indicator}
                                    </td>
                                    <td className="cell-short">{row.type}</td>
                                    <td className="cell-short">
                                        {row.observed_in}
                                    </td>
                                    <td className="cell-short">
                                        {row.feed}
                                        {row.stale ? " (stale)" : ""}
                                    </td>
                                    <td className="cell-long">
                                        {[
                                            row.malware_family,
                                            ...(row.tags || []),
                                        ]
                                            .filter(Boolean)
                                            .join(", ")}
                                    </td>
                                    <td className="cell-short">
                                        {formatWhen(row.first_seen) ||
                                            "unknown"}{" "}
                                        /{" "}
                                        {formatWhen(row.last_seen) || "unknown"}
                                    </td>
                                    <td className="text-break cell-long">
                                        {row.reference}
                                        {row.reference && (
                                            <button
                                                className="btn btn-sm btn-outline-secondary ms-1"
                                                onClick={() =>
                                                    onCopy(row.reference)
                                                }
                                            >
                                                Copy reference
                                            </button>
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
            <p className="small text-muted mb-0">
                {payload.suppressed?.length || 0} matches suppressed by
                allowlists.
            </p>
        </section>
    );
}

const PROVIDER_STATE = {
    ok: "Ready",
    not_configured: "No API key",
    disabled: "Turned off",
    offline: "Unreachable",
    rate_limited: "Rate limited",
    error: "Errors",
    unsupported: "Nothing to look up",
};

function Providers({ online, settings }) {
    const states = new Map((online?.providers || []).map((p) => [p.id, p]));
    const list = settings?.providers?.length
        ? settings.providers
        : online?.providers || [];
    if (!list.length) return null;
    return (
        <details className="intel-providers">
            <summary>
                Providers ({list.filter((p) => p.configured).length} of{" "}
                {list.length} ready)
            </summary>
            <div className="chimera-table-scroll">
                <table
                    className="table table-sm chimera-data-table mb-1"
                    aria-label="Threat-intel providers"
                >
                    <thead>
                        <tr>
                            <th scope="col">Provider</th>
                            <th scope="col">State</th>
                            <th scope="col">Last run</th>
                            <th scope="col">Looks up</th>
                        </tr>
                    </thead>
                    <tbody>
                        {list.map((p) => {
                            const run = states.get(p.id);
                            const state = p.configured
                                ? run?.status || "ok"
                                : "not_configured";
                            return (
                                <tr key={p.id}>
                                    <td className="cell-short">
                                        {label(p.id)}
                                    </td>
                                    <td className="cell-short">
                                        <span
                                            className={`intel-pill is-${state === "ok" ? "harmless" : state === "not_configured" ? "unknown" : "suspicious"}`}
                                        >
                                            {PROVIDER_STATE[state] ||
                                                state.replaceAll("_", " ")}
                                        </span>
                                    </td>
                                    <td className="cell-short">
                                        {run ? `${run.queried} lookups` : "–"}
                                    </td>
                                    <td className="cell-long">
                                        {(p.observable_types || []).join(", ")}
                                    </td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            </div>
            <p className="small text-muted mb-0">
                A provider without a key is skipped. Keys live on the host in{" "}
                <code>/etc/chimera/keys/&lt;provider&gt;</code> (abuse.ch:{" "}
                <code>/etc/chimera/abusech-auth-key</code>); only hashes,
                domains, IPs and URLs are sent, never the sample.
            </p>
        </details>
    );
}

export function ThreatIntelCard({ analysisId, stage, isOffline = false }) {
    const [loaded, setLoaded] = useState(null);
    const [settings, setSettings] = useState(null);
    const [running, setRunning] = useState(null);
    const [lookupError, setLookupError] = useState("");
    const [refreshStarted, setRefreshStarted] = useState(0);
    const [copyError, setCopyError] = useState("");
    useEffect(() => {
        if (isOffline) return;
        let active = true;
        getIntelProviders()
            .then(({ data }) => {
                if (active) setSettings(data);
            })
            .catch(() => {});
        return () => {
            active = false;
        };
    }, [isOffline]);
    useEffect(() => {
        setLoaded(null);
        if (stage || isOffline) return;
        let active = true;
        const controller = new AbortController();
        let timer;
        const deadline = Date.now() + 15 * 60 * 1000;
        const load = () =>
            getIntel(analysisId, { signal: controller.signal })
                .then(({ data }) => {
                    if (active) setLoaded(data);
                })
                .catch((error) => {
                    if (!active) return;
                    setLoaded({ status: "unavailable" });
                    if (
                        error?.response?.status === 404 &&
                        Date.now() < deadline
                    )
                        timer = setTimeout(load, 5000);
                });
        load();
        return () => {
            active = false;
            clearTimeout(timer);
            controller.abort();
        };
    }, [analysisId, stage, isOffline]);
    // Poll until the report shows the result of the job just queued (online lookup or offline re-check).
    useEffect(() => {
        if (!running) return;
        let active = true;
        const controller = new AbortController();
        const timer = setInterval(() => {
            if (Date.now() - refreshStarted >= 180000) {
                setRunning(null);
                setLookupError("Still running; check again later.");
                return;
            }
            getIntel(analysisId, { signal: controller.signal })
                .then(({ data }) => {
                    if (!active) return;
                    const generated = data?.payload?.online?.generated_at;
                    const changed =
                        running === "online"
                            ? generated &&
                              Date.parse(generated) >= refreshStarted
                            : data?.payload?.feeds?.length;
                    setLoaded(data);
                    if (changed) setRunning(null);
                })
                .catch(() => {
                    if (active) setLookupError("Could not load the result.");
                });
        }, 5000);
        return () => {
            active = false;
            clearInterval(timer);
            controller.abort();
        };
    }, [running, analysisId, refreshStarted]);
    const start = async (kind) => {
        setLookupError("");
        setRefreshStarted(Date.now());
        setRunning(kind);
        try {
            await (kind === "online" ? refreshIntel : recheckIntel)(analysisId);
        } catch {
            setRunning(null);
            setLookupError(
                kind === "online"
                    ? "Could not queue online lookup."
                    : "Could not queue the offline re-check.",
            );
        }
    };
    const copy = async (text) => {
        try {
            await navigator.clipboard.writeText(text);
            setCopyError("");
        } catch {
            setCopyError(
                "Copy unavailable; select the reference text to copy it.",
            );
        }
    };
    const current = loaded || stage;
    const payload = current?.payload;
    const online = payload?.online;
    const assessment = current?.assessment;
    const feeds = payload?.feeds || [];
    const results = (online?.results || []).filter(
        (r) => r.status !== "not_configured" && r.status !== "unsupported",
    );
    const hashRows = results.filter(
        (r) => HASH_TYPES.has(r.type) && (r.origin || "sample") === "sample",
    );
    const otherRows = results.filter((r) => !hashRows.includes(r));
    const flagged = results.filter((r) =>
        ["malicious", "suspicious"].includes(r.verdict),
    ).length;
    const offlineMatches = payload?.matches?.length || 0;
    const onlineEnabled = settings?.online_enabled;
    return (
        <section className="card mb-3 intel-card" aria-label="Threat intel">
            <div className="card-body">
                <div className="intel-header">
                    <h5 className="mb-0">Threat intel</h5>
                    {!isOffline ? (
                        <div className="d-flex flex-wrap gap-2 ms-auto">
                            <button
                                className="btn btn-sm btn-outline-secondary"
                                disabled={Boolean(running)}
                                onClick={() => start("offline")}
                                title="Match this analysis against the offline feeds installed now"
                            >
                                {running === "offline"
                                    ? "Re-checking offline feeds"
                                    : "Re-check offline feeds"}
                            </button>
                            <button
                                className="btn btn-sm btn-primary"
                                disabled={Boolean(running) || !onlineEnabled}
                                onClick={() => start("online")}
                            >
                                {running === "online"
                                    ? "Online lookup running"
                                    : online
                                      ? "Run online lookup again"
                                      : "Run online lookup"}
                            </button>
                        </div>
                    ) : null}
                </div>
                {lookupError && (
                    <p role="alert" className="small text-warning-emphasis">
                        {lookupError}
                    </p>
                )}
                {!isOffline && settings?.online_enabled === false && (
                    <p className="small">
                        Online disabled. Set online_enabled = true in the
                        [intel] configuration and start drakrun intel-worker.
                    </p>
                )}
                <div className="intel-summary">
                    <div className="intel-tile">
                        <span className="intel-tile-label">Assessment</span>
                        {assessment ? (
                            <div role="status">
                                <strong>
                                    {assessment.label}: {assessment.basis}
                                </strong>
                                <ul className="intel-list mb-0">
                                    {assessment.reasons?.map((reason) => (
                                        <li key={reason}>{reason}</li>
                                    ))}
                                </ul>
                            </div>
                        ) : (
                            <span className="text-muted">–</span>
                        )}
                    </div>
                    <div className="intel-tile">
                        <span className="intel-tile-label">Offline feeds</span>
                        {feeds.length ? (
                            <>
                                <strong>
                                    {offlineMatches
                                        ? `${offlineMatches} match${offlineMatches === 1 ? "" : "es"}`
                                        : "No match"}
                                </strong>
                                <span className="small text-muted">
                                    {feeds.length} feeds,{" "}
                                    {feeds.some((f) => f.stale)
                                        ? "some stale"
                                        : "fresh"}
                                </span>
                            </>
                        ) : (
                            <span className="badge bg-secondary align-self-start">
                                {!current && !isOffline
                                    ? "Loading offline feed snapshot"
                                    : "Offline feeds missing"}
                            </span>
                        )}
                    </div>
                    <div className="intel-tile">
                        <span className="intel-tile-label">Online lookups</span>
                        {online ? (
                            <>
                                <strong>
                                    {flagged
                                        ? `${flagged} flagged`
                                        : "Nothing flagged"}
                                </strong>
                                <span className="small text-muted">
                                    {results.length} lookups ·{" "}
                                    {
                                        (online.providers || []).filter(
                                            (p) => p.configured,
                                        ).length
                                    }{" "}
                                    providers ·{" "}
                                    {formatWhen(online.generated_at)} ·{" "}
                                    {online.connectivity}
                                </span>
                            </>
                        ) : (
                            <span className="small text-muted">
                                Not run for this analysis
                            </span>
                        )}
                    </div>
                </div>
                {!feeds.length && !isOffline ? (
                    <p className="small text-muted">
                        This report has no offline feed snapshot. If a bundle
                        has been imported since, use “Re-check offline feeds”.
                    </p>
                ) : null}
                {online ? (
                    <>
                        <SampleReputation rows={hashRows} />
                        <NetworkIndicators rows={otherRows} />
                    </>
                ) : null}
                {feeds.length ? (
                    <OfflineFeeds payload={payload} onCopy={copy} />
                ) : null}
                {copyError && (
                    <p role="status" className="small">
                        {copyError}
                    </p>
                )}
                {!isOffline ? (
                    <Providers online={online} settings={settings} />
                ) : null}
            </div>
        </section>
    );
}
