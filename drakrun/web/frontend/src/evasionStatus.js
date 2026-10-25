/**
 * Status/substatus values are the same vocabulary analyses use
 * (queued/started/finished/failed), so scan run status can reuse
 * AnalysisStatusBadge directly - only the CHIMERA score state
 * (pass/warn/fail/incomplete) needs its own vocabulary, handled below.
 */
export function isScanPending(status) {
    return status === "queued" || status === "started";
}

export function isScanFinal(status) {
    return status === "finished" || status === "failed";
}

const SCORE_STATE_LABELS = {
    pass: "Pass",
    warn: "Warn",
    fail: "Fail",
    incomplete: "Incomplete",
};

/**
 * Human-readable label for an EvasionScore.state value. Falls back to the
 * raw value itself for a state this frontend doesn't recognize yet, rather
 * than hiding it - the API is the source of truth for what states exist.
 */
export function scoreStateLabel(state) {
    return SCORE_STATE_LABELS[state] || state || "Unknown";
}
