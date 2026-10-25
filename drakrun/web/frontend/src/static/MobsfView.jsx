import { getMobsf } from "../api.js";
import { useOptionalJson } from "../AnalysisVerdict.jsx";

const BADGE = {
    high: "bg-danger",
    warning: "bg-warning text-dark",
    medium: "bg-warning text-dark",
    dangerous: "bg-danger",
    info: "bg-info text-dark",
    hotspot: "bg-secondary",
    secure: "bg-success",
};

function Badge({ value }) {
    return (
        <span className={`badge ${BADGE[value] || "bg-secondary"}`}>
            {value || "–"}
        </span>
    );
}

function Section({ title, count, children }) {
    return (
        <section className="mb-4">
            <h3 className="h6">
                {title}{" "}
                {count != null ? (
                    <span className="badge bg-secondary">{count}</span>
                ) : null}
            </h3>
            {children}
        </section>
    );
}

function Table({ label, columns, rows }) {
    if (!rows?.length)
        return <p className="small text-muted mb-0">None reported.</p>;
    return (
        <div className="chimera-table-scroll">
            <table
                aria-label={label}
                className="table table-sm chimera-data-table"
            >
                <thead>
                    <tr>
                        {columns.map(([title]) => (
                            <th key={title}>{title}</th>
                        ))}
                    </tr>
                </thead>
                <tbody>
                    {rows.map((row, i) => (
                        <tr key={i}>
                            {columns.map(([title, render, cls]) => (
                                <td key={title} className={cls || "cell-long"}>
                                    {render(row)}
                                </td>
                            ))}
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

// MobSF's static scan of an APK or IPA (chimera-mobsf/1), run in a container without network on the deep queue.
export function MobsfView({ analysisId }) {
    const state = useOptionalJson(getMobsf, analysisId);
    if (state.loading) return <div role="status">Loading MobSF scan…</div>;
    if (state.missing)
        return (
            <div role="status" className="small text-muted">
                {state.polling
                    ? "MobSF has not finished yet: it runs on the deep queue after the fast pass (this updates by itself)."
                    : "No MobSF scan for this file (off on this server: [static] mobsf_enabled)."}
            </div>
        );
    if (state.error)
        return <div role="status">Error: {String(state.error)}</div>;
    const doc = state.data;
    if (doc.error)
        return (
            <div className="alert alert-warning small">
                MobSF scan failed: {doc.error}
            </div>
        );
    const app = doc.app || {};
    const counts = doc.counts || {};
    const ios = doc.format === "ipa" || Boolean(app.bundle_id);
    return (
        <div>
            <p className="small text-muted">
                MobSF {doc.image?.split(":").pop()} scanned the{" "}
                {ios ? "IPA" : "APK"} in a container with no network; nothing
                was sent off the host. Its findings are informational and do not
                change the verdict.
            </p>
            <div className="static-metrics mb-3">
                {[
                    [
                        "Security score",
                        doc.security_score != null
                            ? `${doc.security_score}/100`
                            : "–",
                    ],
                    ["App", app.app_name || "–"],
                    ...(ios
                        ? [
                              ["Bundle ID", app.bundle_id || "–"],
                              [
                                  "Version / minimum iOS",
                                  `${app.app_version ?? "–"} / ${app.min_os_version ?? "–"}`,
                              ],
                          ]
                        : [
                              ["Package", app.package_name || "–"],
                              [
                                  "SDK (min / target)",
                                  `${app.min_sdk ?? "–"} / ${app.target_sdk ?? "–"}`,
                              ],
                          ]),
                    [
                        "Findings",
                        `${counts.high ?? 0} high · ${counts.warning ?? 0} warning · ${counts.info ?? 0} info`,
                    ],
                    [
                        "Permissions",
                        `${doc.permissions?.filter((p) => p.status === "dangerous").length ?? 0} dangerous of ${doc.permissions_total ?? 0}`,
                    ],
                    ["Trackers", doc.trackers?.length ?? 0],
                    ...(ios
                        ? []
                        : [
                              [
                                  "Malware-typical permissions",
                                  doc.malware_permissions?.matched ?? "–",
                              ],
                          ]),
                ].map(([label, value]) => (
                    <div className="card" key={label}>
                        <div className="card-body p-3">
                            <div className="small text-muted">{label}</div>
                            <div className="fw-semibold text-break">
                                {value}
                            </div>
                        </div>
                    </div>
                ))}
            </div>
            <Section title="Security findings" count={doc.findings?.length}>
                <Table
                    label="MobSF security findings"
                    rows={doc.findings}
                    columns={[
                        [
                            "Severity",
                            (r) => <Badge value={r.severity} />,
                            "cell-short",
                        ],
                        ["Finding", (r) => r.title],
                        ["Area", (r) => r.section, "cell-short"],
                        ["Detail", (r) => r.description],
                    ]}
                />
            </Section>
            <Section title="Permissions" count={doc.permissions_total}>
                <Table
                    label={ios ? "iOS permissions" : "Android permissions"}
                    rows={doc.permissions}
                    columns={[
                        [
                            "Status",
                            (r) => <Badge value={r.status} />,
                            "cell-short",
                        ],
                        ["Permission", (r) => r.name, "cell-mono cell-short"],
                        ["What it allows", (r) => r.info],
                        ["Detail", (r) => r.description],
                    ]}
                />
            </Section>
            <Section title="Code findings" count={doc.code_findings?.length}>
                <Table
                    label="MobSF code findings"
                    rows={doc.code_findings}
                    columns={[
                        [
                            "Severity",
                            (r) => <Badge value={r.severity} />,
                            "cell-short",
                        ],
                        ["Rule", (r) => r.id, "cell-mono cell-short"],
                        ["Description", (r) => r.description],
                        [
                            "Standards",
                            (r) =>
                                [r.cwe, r.owasp, r.masvs]
                                    .filter(Boolean)
                                    .join(" · "),
                        ],
                        ["Files", (r) => r.files, "cell-num"],
                    ]}
                />
            </Section>
            {ios ? (
                <>
                    <Section
                        title="Binary findings"
                        count={doc.binary_findings?.length}
                    >
                        <Table
                            label="MobSF binary findings"
                            rows={doc.binary_findings}
                            columns={[
                                [
                                    "Severity",
                                    (r) => <Badge value={r.severity} />,
                                    "cell-short",
                                ],
                                ["Finding", (r) => r.title],
                                ["Detail", (r) => r.description],
                                [
                                    "Standards",
                                    (r) =>
                                        [r.cwe, r.owasp, r.masvs]
                                            .filter(Boolean)
                                            .join(" · "),
                                ],
                            ]}
                        />
                    </Section>
                    <Section
                        title="Binary hardening"
                        count={doc.binary_hardening?.length}
                    >
                        <Table
                            label="Binary hardening"
                            rows={doc.binary_hardening}
                            columns={[
                                [
                                    "Severity",
                                    (r) => <Badge value={r.severity} />,
                                    "cell-short",
                                ],
                                [
                                    "Protection",
                                    (r) => r.title.replaceAll("_", " "),
                                    "cell-short",
                                ],
                                ["Detail", (r) => r.description],
                            ]}
                        />
                    </Section>
                    <Section
                        title="App Transport Security"
                        count={doc.ats_findings?.length}
                    >
                        <Table
                            label="App Transport Security findings"
                            rows={doc.ats_findings}
                            columns={[
                                [
                                    "Severity",
                                    (r) => <Badge value={r.severity} />,
                                    "cell-short",
                                ],
                                ["Finding", (r) => r.title],
                                ["Detail", (r) => r.description],
                            ]}
                        />
                    </Section>
                </>
            ) : null}
            {ios ? null : (
                <>
                    <Section
                        title="Manifest findings"
                        count={doc.manifest_findings?.length}
                    >
                        <Table
                            label="MobSF manifest findings"
                            rows={doc.manifest_findings}
                            columns={[
                                [
                                    "Severity",
                                    (r) => <Badge value={r.severity} />,
                                    "cell-short",
                                ],
                                ["Finding", (r) => r.title],
                                ["Detail", (r) => r.description],
                            ]}
                        />
                    </Section>
                    <Section
                        title="Behaviour in the code"
                        count={doc.behaviour?.length}
                    >
                        <Table
                            label="MobSF behaviour"
                            rows={doc.behaviour}
                            columns={[
                                ["Rule", (r) => r.id, "cell-mono cell-short"],
                                ["Behaviour", (r) => r.description],
                                [
                                    "Kind",
                                    (r) => [].concat(r.label || []).join(", "),
                                    "cell-short",
                                ],
                                ["Files", (r) => r.files, "cell-num"],
                            ]}
                        />
                    </Section>
                    <Section
                        title="Sensitive Android APIs"
                        count={doc.android_api?.length}
                    >
                        <Table
                            label="Android API use"
                            rows={doc.android_api}
                            columns={[
                                ["API", (r) => r.description || r.id],
                                ["Rule", (r) => r.id, "cell-mono cell-short"],
                                ["Files", (r) => r.files, "cell-num"],
                            ]}
                        />
                    </Section>
                    <Section
                        title="Network security config"
                        count={doc.network_security?.length}
                    >
                        <Table
                            label="Network security findings"
                            rows={doc.network_security}
                            columns={[
                                [
                                    "Severity",
                                    (r) => <Badge value={r.severity} />,
                                    "cell-short",
                                ],
                                [
                                    "Scope",
                                    (r) => [].concat(r.scope || []).join(", "),
                                    "cell-mono cell-short",
                                ],
                                ["Finding", (r) => r.description],
                            ]}
                        />
                    </Section>
                    <Section
                        title="Signing certificate"
                        count={doc.certificate?.findings?.length}
                    >
                        {doc.certificate?.info ? (
                            <pre className="small mb-2 text-wrap">
                                {doc.certificate.info}
                            </pre>
                        ) : null}
                        <Table
                            label="Certificate findings"
                            rows={doc.certificate?.findings}
                            columns={[
                                [
                                    "Severity",
                                    (r) => <Badge value={r.severity} />,
                                    "cell-short",
                                ],
                                ["Finding", (r) => r.title || r.description],
                                ["Detail", (r) => r.description],
                            ]}
                        />
                    </Section>
                    <Section
                        title="Packers, obfuscators and anti-analysis (APKiD)"
                        count={doc.apkid?.length}
                    >
                        <Table
                            label="APKiD"
                            rows={doc.apkid}
                            columns={[
                                ["File", (r) => r.file, "cell-mono cell-short"],
                                [
                                    "Category",
                                    (r) => r.category?.replaceAll("_", " "),
                                    "cell-short",
                                ],
                                [
                                    "Found",
                                    (r) => [].concat(r.values || []).join(", "),
                                ],
                            ]}
                        />
                    </Section>
                </>
            )}
            {doc.secrets_total ? (
                <Section
                    title="Possible secrets in resources"
                    count={doc.secrets_total}
                >
                    <ul className="small font-monospace mb-0">
                        {doc.secrets.map((v, i) => (
                            <li key={i} className="text-break">
                                {v}
                            </li>
                        ))}
                    </ul>
                </Section>
            ) : null}
            <Section title="Trackers" count={doc.trackers?.length}>
                <Table
                    label="Trackers"
                    rows={doc.trackers}
                    columns={[
                        ["Tracker", (r) => r.name, "cell-short"],
                        ["Category", (r) => r.categories],
                    ]}
                />
            </Section>
            <Section
                title="Domains and URLs in the code"
                count={(doc.domains?.length || 0) + (doc.urls?.length || 0)}
            >
                <ul className="small font-monospace mb-0">
                    {[...(doc.domains || []), ...(doc.urls || [])].map((v) => (
                        <li key={v} className="text-break">
                            {v}
                        </li>
                    ))}
                </ul>
            </Section>
        </div>
    );
}
