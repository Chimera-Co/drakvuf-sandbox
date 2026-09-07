export function AnalysisStatusBadge({ status, substatus }) {
    // Bootstrap fallback classes are kept so the badge still reads correctly if
    // the CHIMERA theme stylesheet is ever absent. The Solarized semantic
    // colouring is applied by `.chimera-status[data-status]` in chimera-theme.css.
    // Status values and the mapping itself are unchanged.
    const statusStyle =
        {
            queued: "bg-primary",
            started: "bg-info",
            finished: "bg-success",
            failed: "bg-danger",
        }[status] || "bg-secondary";
    return (
        <div
            className={`badge chimera-status ${statusStyle} me-2 p-2`}
            data-status={status}
        >
            {status}
            {substatus ? ` (${substatus})` : ""}
        </div>
    );
}
