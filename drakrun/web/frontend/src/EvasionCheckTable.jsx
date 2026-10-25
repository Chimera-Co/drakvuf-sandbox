import { CATEGORY_LABELS } from "./EvasionCharts.jsx";

/**
 * A flat, capability-driven drill-down over every check any tool in this
 * scan produced, grouped by CHIMERA's four fixed categories. Nothing here
 * assumes which or how many tools ran - each check already carries its own
 * `tool` id (from NormalizedCheck), so a third verifier's checks show up in
 * the same table with no code change.
 */

const STATUS_CLASSES = {
    clean: "text-success",
    detected: "text-danger fw-bold",
    error: "text-warning",
    skipped: "text-muted",
};

function formatEvidence(evidence) {
    if (evidence === null || typeof evidence === "undefined") return "-";
    if (typeof evidence === "string") return evidence;
    try {
        return JSON.stringify(evidence);
    } catch {
        return String(evidence);
    }
}

function groupByCategory(checks) {
    const groups = {};
    for (const check of checks) {
        if (!groups[check.category]) groups[check.category] = [];
        groups[check.category].push(check);
    }
    return groups;
}

function CategorySection({ category, checks }) {
    return (
        <details className="mb-3" open>
            <summary className="fw-bold" style={{ cursor: "pointer" }}>
                {CATEGORY_LABELS[category] || category} ({checks.length})
            </summary>
            <div className="datatable-container mt-2">
                <table className="datatable-table">
                    <thead>
                        <tr>
                            <th>Tool</th>
                            <th>Status</th>
                            <th>Severity</th>
                            <th>Check</th>
                            <th>Description</th>
                            <th>Evidence</th>
                            <th>Remediation</th>
                        </tr>
                    </thead>
                    <tbody>
                        {checks.map((check, idx) => (
                            <tr key={`${check.tool}-${check.id}-${idx}`}>
                                <td>{check.tool}</td>
                                <td
                                    className={
                                        STATUS_CLASSES[check.status] || ""
                                    }
                                >
                                    {check.status}
                                </td>
                                <td>{check.severity}</td>
                                <td>{check.name}</td>
                                <td>{check.description}</td>
                                <td className="font-monospace small">
                                    {formatEvidence(check.evidence)}
                                </td>
                                <td>{check.remediation || "-"}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </details>
    );
}

export function EvasionCheckTable({ toolResults }) {
    const checks = (toolResults || []).flatMap((tr) => tr.checks || []);
    if (checks.length === 0) {
        return (
            <div className="text-muted small">
                No individual checks were recorded for this scan.
            </div>
        );
    }
    const groups = groupByCategory(checks);
    return (
        <div>
            {Object.entries(groups).map(([category, categoryChecks]) => (
                <CategorySection
                    key={category}
                    category={category}
                    checks={categoryChecks}
                />
            ))}
        </div>
    );
}
