import { useEffect, useState } from "react";
import axios from "axios";

export function ThreatIntelCard({ analysisId, stage, isOffline = false }) {
    const [loaded, setLoaded] = useState(null);
    useEffect(() => {
        setLoaded(null);
        if (stage || isOffline) return;
        let active = true;
        const controller = new AbortController();
        let timer;
        const deadline = Date.now() + 15 * 60 * 1000;
        const load = () =>
            axios
                .get(`/intel/${analysisId}`, { signal: controller.signal })
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
    const current = stage || loaded;
    const payload = current?.payload;
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
