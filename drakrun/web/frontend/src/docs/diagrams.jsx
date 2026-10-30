/**
 * Diagrams shared by the Home page and the docs (```diagram <name>``` in a Markdown page).
 * Colours come from the theme tokens through docs.css classes, so every colour scheme and dark mode work.
 */

export const PIPELINE_STEPS = [
    {
        name: "Upload",
        where: "Web console / REST API",
        text: "File, platform (Windows, Linux, Android, iOS) and mode: combined, dynamic only or static only. The sample is stored read-only and is never executable on the host.",
    },
    {
        name: "Static pass",
        where: "Static-analysis VM, no network",
        text: "Real file type, hashes, strings, IOCs, PE, ELF, PDF, Office and script parsers, YARA; then capa, FLOSS and the Ghidra decompiler. Android and iOS apps go to MobSF.",
    },
    {
        name: "Detonation",
        where: "Xen HVM guest + DRAKVUF",
        text: "A disposable guest is restored from its snapshot, the sample is started, and DRAKVUF plugins trace it from outside the guest. Traffic goes to INetSim and is captured.",
    },
    {
        name: "Post-processing",
        where: "dom0 worker",
        text: "Logs are split and indexed, the process tree and behaviour summary are built, capa maps behaviour to ATT&CK, and memory dumps are scanned for unpacked code.",
    },
    {
        name: "Verdict",
        where: "Classifier process",
        text: "Dynamic and static features go to the models; their scores are fused into one label with per-part explanations.",
    },
    {
        name: "Threat intel",
        where: "Host intel worker",
        text: "Hashes and network indicators are checked against offline feeds, Maltrail family/APT trails and, when enabled, VirusTotal (lookups only, never uploads).",
    },
    {
        name: "Report",
        where: "Console",
        text: "Verdict, static workspace, process tree, ATT&CK matrix, logs, PCAP, screenshots and a self-contained HTML report.",
    },
];

export function PipelineDiagram({ compact = false }) {
    return (
        <ol
            className={`chimera-pipeline ${compact ? "chimera-pipeline--compact" : ""}`}
            aria-label="Analysis pipeline"
        >
            {PIPELINE_STEPS.map((step, idx) => (
                <li key={step.name} className="chimera-pipeline__step">
                    <div className="chimera-pipeline__num" aria-hidden="true">
                        {idx + 1}
                    </div>
                    <div className="chimera-pipeline__body">
                        <div className="chimera-pipeline__name">
                            {step.name}
                        </div>
                        <div className="chimera-pipeline__where">
                            {step.where}
                        </div>
                        {compact ? null : (
                            <p className="chimera-pipeline__text">
                                {step.text}
                            </p>
                        )}
                    </div>
                </li>
            ))}
        </ol>
    );
}

function Box({ x, y, w, h = 60, title, sub, tone = "" }) {
    return (
        <g className={`chimera-svg-box ${tone}`}>
            <rect x={x} y={y} width={w} height={h} rx="6" />
            <text
                x={x + w / 2}
                y={y + (sub ? h / 2 - 5 : h / 2 + 5)}
                className="chimera-svg-title"
            >
                {title}
            </text>
            {sub ? (
                <text
                    x={x + w / 2}
                    y={y + h / 2 + 14}
                    className="chimera-svg-sub"
                >
                    {sub}
                </text>
            ) : null}
        </g>
    );
}

function Arrow({ d, dashed = false, blocked = false }) {
    return (
        <path
            d={d}
            className={`chimera-svg-arrow ${dashed ? "is-dashed" : ""} ${blocked ? "is-blocked" : ""}`}
            markerEnd={blocked ? undefined : "url(#chimera-arrowhead)"}
        />
    );
}

function ArrowMarker() {
    return (
        <defs>
            <marker
                id="chimera-arrowhead"
                viewBox="0 0 10 10"
                refX="9"
                refY="5"
                markerWidth="7"
                markerHeight="7"
                orient="auto-start-reverse"
            >
                <path d="M0 0 L10 5 L0 10 z" className="chimera-svg-head" />
            </marker>
        </defs>
    );
}

export function ArchitectureDiagram() {
    return (
        <figure className="chimera-figure">
            <div className="chimera-figure__scroll">
                <svg
                    viewBox="0 0 960 600"
                    role="img"
                    aria-labelledby="chimera-arch-title"
                    className="chimera-svg"
                >
                    <title id="chimera-arch-title">
                        CHIMERA components: console, API, queues, workers,
                        DRAKVUF, static VM, containment and guests on Xen
                    </title>
                    <ArrowMarker />
                    <rect
                        x="12"
                        y="8"
                        width="936"
                        height="350"
                        rx="10"
                        className="chimera-svg-zone"
                    />
                    <text x="26" y="30" className="chimera-svg-zone-label">
                        dom0 (Debian 12, Xen control domain)
                    </text>
                    <rect
                        x="12"
                        y="372"
                        width="936"
                        height="138"
                        rx="10"
                        className="chimera-svg-zone is-hostile"
                    />
                    <text x="26" y="394" className="chimera-svg-zone-label">
                        Guests (domU)
                    </text>

                    <Box
                        x={30}
                        y={44}
                        w={180}
                        title="Browser"
                        sub="React console"
                        tone="is-accent"
                    />
                    <Box
                        x={262}
                        y={44}
                        w={200}
                        title="Web API"
                        sub="127.0.0.1:5000"
                    />
                    <Box
                        x={514}
                        y={44}
                        w={200}
                        title="Redis + RQ"
                        sub="job queues"
                    />
                    <Box
                        x={766}
                        y={44}
                        w={164}
                        title="Results store"
                        sub="/var/lib/drakrun"
                    />
                    <Arrow d="M210 74 L258 74" />
                    <Arrow d="M462 74 L510 74" />
                    <Arrow d="M714 74 L762 74" dashed />

                    <path
                        d="M614 104 L614 124 M120 124 L840 124"
                        className="chimera-svg-bus"
                    />
                    <Arrow d="M120 124 L120 146" />
                    <Arrow d="M360 124 L360 146" />
                    <Arrow d="M600 124 L600 146" />
                    <Arrow d="M840 124 L840 146" />

                    <Box
                        x={30}
                        y={150}
                        w={180}
                        title="Analysis workers"
                        sub="drakrun-worker@N"
                    />
                    <Box
                        x={262}
                        y={150}
                        w={200}
                        title="Static workers"
                        sub="fast + deep"
                    />
                    <Box
                        x={514}
                        y={150}
                        w={172}
                        title="Intel worker"
                        sub="feeds, trails, VT"
                    />
                    <Box
                        x={722}
                        y={150}
                        w={208}
                        title="Evasion workers"
                        sub="PERDEDOR, al-khaser"
                    />

                    <Box
                        x={30}
                        y={262}
                        w={180}
                        title="DRAKVUF + LibVMI"
                        sub="VMI plugins"
                        tone="is-accent"
                    />
                    <Box
                        x={262}
                        y={262}
                        w={200}
                        title="Static VM"
                        sub="PVH, no network"
                    />
                    <Box
                        x={514}
                        y={262}
                        w={172}
                        title="Containment"
                        sub="fail-closed"
                    />
                    <Box
                        x={722}
                        y={262}
                        w={208}
                        title="INetSim"
                        sub="netns chimera-inet"
                    />
                    <Arrow d="M120 210 L120 258" />
                    <Arrow d="M360 210 L360 258" />
                    <Arrow d="M686 292 L718 292" />
                    <Arrow d="M826 210 L826 236 L180 236 L180 258" dashed />

                    <Box
                        x={30}
                        y={410}
                        w={180}
                        title="Windows 10 guest"
                        sub="from snapshot"
                        tone="is-hostile"
                    />
                    <Box
                        x={262}
                        y={410}
                        w={200}
                        title="Linux guest"
                        sub="Debian 12 desktop"
                        tone="is-hostile"
                    />
                    <Box
                        x={722}
                        y={410}
                        w={208}
                        title="LAN / Internet"
                        sub="never reached"
                        tone="is-muted"
                    />
                    <Arrow d="M120 322 L120 406" dashed />
                    <Arrow d="M190 322 L320 406" dashed />
                    <text x="128" y="366" className="chimera-svg-label">
                        VMI
                    </text>
                    <Arrow d="M462 440 L600 440 L600 326" />
                    <text x="470" y="430" className="chimera-svg-label">
                        guest network (drakN)
                    </text>
                    <Arrow d="M686 312 L770 406" blocked />
                    <text
                        x="736"
                        y="364"
                        className="chimera-svg-label is-blocked"
                    >
                        ✕ dropped
                    </text>

                    <rect
                        x="12"
                        y="524"
                        width="936"
                        height="60"
                        rx="10"
                        className="chimera-svg-xen"
                    />
                    <text x="480" y="550" className="chimera-svg-title">
                        Xen 4.19 hypervisor
                    </text>
                    <text x="480" y="570" className="chimera-svg-sub">
                        HVM guests · EPT · altp2m views · vm_event
                    </text>
                </svg>
            </div>
            <figcaption>
                Workers take jobs from Redis queues. Analysis and evasion
                workers drive the guests through DRAKVUF; the static workers
                send files to their own network-less VM; every result is written
                under <code>/var/lib/drakrun</code> and read back by the API.
            </figcaption>
        </figure>
    );
}

export function ContainmentDiagram() {
    const chain = [
        ["Guest vm-N", "10.13.N.2, hostile", "is-hostile"],
        ["Bridge drakN", "10.13.N.1/24, vif ports only", ""],
        ["CHIMERA_RAW", "raw: anti-spoofing, link-local drop", ""],
        ["CHIMERA_DNAT", "nat: all TCP/UDP/ICMP → 10.99.0.2", ""],
        ["CHIMERA_GUARD", "FORWARD: only to 10.99.0.2, else drop", ""],
        ["INetSim", "netns chimera-inet, no default route", "is-accent"],
    ];
    return (
        <figure className="chimera-figure">
            <div className="chimera-figure__scroll">
                <svg
                    viewBox="0 0 640 560"
                    role="img"
                    aria-labelledby="chimera-net-title"
                    className="chimera-svg chimera-svg--narrow"
                >
                    <title id="chimera-net-title">
                        Guest traffic path through the CHIMERA containment
                        chains to INetSim
                    </title>
                    <ArrowMarker />
                    {chain.map(([title, sub, tone], idx) => (
                        <g key={title}>
                            <Box
                                x={20}
                                y={20 + idx * 90}
                                w={360}
                                h={58}
                                title={title}
                                sub={sub}
                                tone={tone}
                            />
                            {idx < chain.length - 1 ? (
                                <Arrow
                                    d={`M200 ${78 + idx * 90} L200 ${106 + idx * 90}`}
                                />
                            ) : null}
                        </g>
                    ))}
                    <Box
                        x={430}
                        y={110}
                        w={190}
                        h={58}
                        title="CHIMERA_IN"
                        sub="to dom0: DHCP only"
                        tone="is-muted"
                    />
                    <Box
                        x={430}
                        y={200}
                        w={190}
                        h={58}
                        title="CHIMERA6"
                        sub="IPv6: drop all"
                        tone="is-muted"
                    />
                    <Box
                        x={430}
                        y={380}
                        w={190}
                        h={58}
                        title="Uplink"
                        sub="LAN / Internet"
                        tone="is-muted"
                    />
                    <Arrow d="M380 139 L426 139" dashed />
                    <Arrow d="M380 160 L426 229" dashed />
                    <Arrow d="M380 409 L430 409" blocked />
                    <text
                        x="398"
                        y="400"
                        className="chimera-svg-label is-blocked"
                    >
                        ✕
                    </text>
                </svg>
            </div>
            <figcaption>
                Every guest packet passes the CHIMERA chains. Whatever the guest
                sends, the only host it can reach is INetSim, and dom0 answers
                DHCP only.
            </figcaption>
        </figure>
    );
}

export const DIAGRAMS = {
    pipeline: PipelineDiagram,
    architecture: ArchitectureDiagram,
    containment: ContainmentDiagram,
};
