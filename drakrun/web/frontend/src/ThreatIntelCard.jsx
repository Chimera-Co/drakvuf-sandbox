import { useEffect, useState } from "react";
import { getIntel, getIntelProviders, refreshIntel } from "./intelApi.js";

export function ThreatIntelCard({ analysisId, stage, isOffline = false }) {
    const [loaded, setLoaded] = useState(null);
    const [settings, setSettings] = useState(null);
    const [running, setRunning] = useState(false);
    const [lookupError, setLookupError] = useState("");
    const [refreshStarted, setRefreshStarted] = useState(0);
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
        if (!running) return;
        let active = true;
        const controller = new AbortController();
        const timer = setInterval(() => {
            if (Date.now() - refreshStarted >= 180000) {
                setRunning(false);
                setLookupError("Lookup still pending; check again later.");
                return;
            }
            getIntel(analysisId, { signal: controller.signal })
                .then(({ data }) => {
                    if (!active) return;
                    setLoaded(data);
                    const generated = data?.payload?.online?.generated_at;
                    if (generated && Date.parse(generated) >= refreshStarted)
                        setRunning(false);
                })
                .catch(() => {
                    if (active) setLookupError("Could not load lookup status.");
                });
        }, 5000);
        return () => {
            active = false;
            clearInterval(timer);
            controller.abort();
        };
    }, [running, analysisId, refreshStarted]);
    const startLookup = async () => {
        setLookupError("");
        setRefreshStarted(Date.now());
        setRunning(true);
        try {
            await refreshIntel(analysisId);
        } catch {
            setRunning(false);
            setLookupError("Could not queue online lookup.");
        }
    };
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
    const current = loaded || stage;
    const payload = current?.payload;
    const online = payload?.online;
    const assessment = current?.assessment;
    const feeds = payload?.feeds || [];
    const matches = payload?.matches || [];
    const dates = [...new Set(feeds.map((feed) => feed.fetched_at))].join(", ");
    const [copyError, setCopyError] = useState("");
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
    return (
        <section className="card mb-3" aria-label="Threat intel">
            <div className="card-body">
                <h5>Threat intel</h5>
                {assessment && (
                    <div role="status">
                        <strong>
                            {assessment.label}: {assessment.basis}
                        </strong>
                        <ul>
                            {assessment.reasons?.map((reason) => (
                                <li key={reason}>{reason}</li>
                            ))}
                        </ul>
                    </div>
                )}
                {!isOffline && settings?.online_enabled === false && (
                    <p>
                        Online disabled. Set online_enabled = true in the
                        [intel] configuration and start drakrun intel-worker.
                    </p>
                )}
                {!isOffline && (
                    <button
                        className="btn btn-outline-secondary mb-2"
                        disabled={running || !settings?.online_enabled}
                        onClick={startLookup}
                    >
                        {running
                            ? "Online lookup running"
                            : "Run online lookup"}
                    </button>
                )}
                {lookupError && <p role="alert">{lookupError}</p>}
                {online && (
                    <>
                        <p>Connectivity: {online.connectivity}</p>
                        <div aria-label="Provider status">
                            {online.providers?.map((provider) => (
                                <span key={provider.id} className="me-3">
                                    {provider.id}:{" "}
                                    {provider.status === "ok"
                                        ? "ran"
                                        : provider.status.replaceAll(
                                              "_",
                                              " ",
                                          )}{" "}
                                    ({provider.queried})
                                </span>
                            ))}
                        </div>
                        <div className="chimera-table-scroll">
                            <table className="table table-sm">
                                <thead>
                                    <tr>
                                        {[
                                            "Provider",
                                            "Observable",
                                            "Verdict",
                                            "Detections",
                                            "Family / tags",
                                            "First / last seen",
                                            "Reference",
                                        ].map((label) => (
                                            <th key={label} scope="col">
                                                {label}
                                            </th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody>
                                    {online.results?.map((row, index) => (
                                        <tr key={index}>
                                            <td>{row.provider}</td>
                                            <td>{row.observable}</td>
                                            <td>
                                                {row.status === "ok"
                                                    ? row.verdict
                                                    : row.status.replaceAll(
                                                          "_",
                                                          " ",
                                                      )}
                                            </td>
                                            <td>
                                                {row.detections
                                                    ? `${row.detections.malicious || 0}/${row.detections.total || 0}`
                                                    : "—"}
                                            </td>
                                            <td>
                                                {[
                                                    row.family,
                                                    ...(row.tags || []),
                                                ]
                                                    .filter(Boolean)
                                                    .join(", ")}
                                            </td>
                                            <td>
                                                {row.first_seen || "unknown"} /{" "}
                                                {row.last_seen || "unknown"}
                                            </td>
                                            <td>
                                                {row.permalink &&
                                                    /^https:\/\//.test(
                                                        row.permalink,
                                                    ) && (
                                                        <a
                                                            href={row.permalink}
                                                            target="_blank"
                                                            rel="noopener noreferrer"
                                                        >
                                                            Open provider
                                                        </a>
                                                    )}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </>
                )}
                {!feeds.length && (
                    <p>
                        No offline feed bundle is installed on the host. Import
                        one with <code>drakrun intel import bundle.tar.gz</code>{" "}
                        (needs <code>[intel] enabled = true</code>).
                    </p>
                )}
                {!payload ? (
                    <span className="badge bg-secondary">
                        {!current && !isOffline
                            ? "Loading offline feed snapshot"
                            : "Offline feeds missing"}
                    </span>
                ) : (
                    <>
                        {(payload.failures || []).map((feed) => (
                            <span
                                key={feed.name}
                                className="badge bg-secondary me-2"
                            >
                                {feed.name}: missing
                            </span>
                        ))}
                        <div className="d-flex flex-wrap gap-2 mb-2">
                            {feeds.map((feed) => (
                                <span
                                    key={feed.name}
                                    className={`badge ${feed.stale ? "bg-warning text-dark" : "bg-success"}`}
                                    title={`Fetched ${feed.fetched_at}; expires ${feed.expires_at}`}
                                >
                                    {feed.name}:{" "}
                                    {feed.stale ? "stale" : "fresh"}
                                </span>
                            ))}
                        </div>
                        {!matches.length ? (
                            <p>
                                No match in the offline feeds (dated{" "}
                                {dates || "unknown"}): not a verdict of benign
                            </p>
                        ) : (
                            <div className="table-responsive">
                                <table className="table table-sm">
                                    <thead>
                                        <tr>
                                            {[
                                                "Indicator",
                                                "Type",
                                                "Where observed",
                                                "Feed",
                                                "Family / tags",
                                                "Dates",
                                                "Reference",
                                            ].map((label) => (
                                                <th key={label} scope="col">
                                                    {label}
                                                </th>
                                            ))}
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {matches.map((row, index) => (
                                            <tr key={index}>
                                                <td className="font-monospace text-break">
                                                    {row.indicator}
                                                </td>
                                                <td>{row.type}</td>
                                                <td>{row.observed_in}</td>
                                                <td>
                                                    {row.feed}
                                                    {row.stale
                                                        ? " (stale)"
                                                        : ""}
                                                </td>
                                                <td>
                                                    {[
                                                        row.malware_family,
                                                        ...(row.tags || []),
                                                    ]
                                                        .filter(Boolean)
                                                        .join(", ")}
                                                </td>
                                                <td>
                                                    {row.first_seen ||
                                                        "unknown"}{" "}
                                                    /{" "}
                                                    {row.last_seen || "unknown"}
                                                </td>
                                                <td className="text-break">
                                                    {row.reference}
                                                    {row.reference && (
                                                        <button
                                                            className="btn btn-sm btn-outline-secondary ms-1"
                                                            onClick={() =>
                                                                copy(
                                                                    row.reference,
                                                                )
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
                        <p className="small text-muted">
                            {payload.suppressed?.length || 0} matches suppressed
                            by allowlists.
                        </p>
                        {copyError && <p role="status">{copyError}</p>}
                    </>
                )}
            </div>
        </section>
    );
}
