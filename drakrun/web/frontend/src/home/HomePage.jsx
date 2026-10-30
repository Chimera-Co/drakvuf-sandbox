import { Link } from "react-router-dom";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
    faArrowRight,
    faBook,
    faBrain,
    faCode,
    faDesktop,
    faEye,
    faFolder,
    faGlobe,
    faLayerGroup,
    faMemory,
    faMicroscope,
    faNetworkWired,
    faShieldHalved,
    faUpload,
} from "@fortawesome/free-solid-svg-icons";
import { ChimeraLogo } from "../ChimeraLogo.jsx";
import { PipelineDiagram } from "../docs/diagrams.jsx";
import "../docs/docs.css";

const FEATURES = [
    [
        faEye,
        "Agentless tracing",
        "DRAKVUF watches the guest from the hypervisor: processes, API calls, files, registry, sockets, TLS keys and memory dumps, with no monitoring agent for malware to find.",
    ],
    [
        faDesktop,
        "Windows and Linux guests",
        "Windows 10 and a Debian 12 desktop, each restored from a clean snapshot for every analysis and destroyed afterwards. Live VNC view and screenshots.",
    ],
    [
        faMicroscope,
        "Static analysis",
        "Files identified by content (PE, ELF, Mach-O, PDF, Office, RTF, LNK, archives, scripts and more), format parsers, YARA, capa, FLOSS and a Ghidra decompiler.",
    ],
    [
        faLayerGroup,
        "Isolated static VM",
        "Parsers run in a Xen guest with no network interface and a read-only disk, so a parser exploit lands in a throwaway VM, not on the host.",
    ],
    [
        faMemory,
        "Memory-dump scanning",
        "Regions DRAKVUF dumps during the run (injected or unpacked code) go through the same analyzers, often showing code the file on disk hides.",
    ],
    [
        faBrain,
        "Fused ML verdict",
        "A behaviour model and file models score separately; the scores are fused into one label with the reasons from each part.",
    ],
    [
        faGlobe,
        "Threat intelligence",
        "Offline abuse.ch feeds and warninglists, Maltrail family and APT trails, and opt-in VirusTotal hash lookups. Samples are never uploaded.",
    ],
    [
        faNetworkWired,
        "Network containment",
        "Guests reach only INetSim in its own network namespace through a fail-closed firewall; the full capture is kept as PCAP.",
    ],
    [
        faShieldHalved,
        "Anti-detection hardening",
        "Real firmware and hardware identities, hidden hypervisor CPUID leaves, simulated mouse input and a lived-in guest, measured with evasion test suites.",
    ],
    [
        faCode,
        "Reports and API",
        "ATT&CK matrix, process tree, per-process logs, decompiled code, a self-contained HTML report and a REST API with OpenAPI docs.",
    ],
];

const START = [
    [
        "overview",
        "Overview",
        "What the project is and how the docs are organised.",
    ],
    [
        "concepts-vmi",
        "Concepts",
        "VMI, Xen HVM, altp2m and the DRAKVUF plugins.",
    ],
    [
        "architecture",
        "Architecture",
        "Services, queues, storage and trust boundaries.",
    ],
    [
        "build-host-xen",
        "Build guide",
        "From a blank Debian host to a working sandbox.",
    ],
    [
        "operating",
        "Operating",
        "Uploading, reading reports and running the services.",
    ],
    [
        "limitations",
        "Limitations",
        "What CHIMERA does not do yet, and what is next.",
    ],
];

export default function HomePage() {
    return (
        <div className="chimera-home">
            <section className="chimera-home__hero">
                <div className="chimera-home__hero-inner">
                    <ChimeraLogo
                        size={112}
                        variant="light"
                        className="chimera-home__mark"
                    />
                    <div>
                        <h1 className="chimera-home__title">CHIMERA</h1>
                        <p className="chimera-home__lead">
                            A malware sandbox that watches samples from outside
                            the operating system.
                        </p>
                        <p className="chimera-home__sub">
                            Xen and DRAKVUF virtual-machine introspection, a
                            network-less static-analysis VM, a machine-learning
                            verdict and threat intelligence, in one console.
                        </p>
                        <div className="chimera-home__actions">
                            <Link className="btn btn-primary" to="/upload">
                                <FontAwesomeIcon icon={faUpload} /> Upload a
                                sample
                            </Link>
                            <Link
                                className="btn chimera-home__btn-ghost"
                                to="/"
                            >
                                <FontAwesomeIcon icon={faFolder} /> Analyses
                            </Link>
                            <Link
                                className="btn chimera-home__btn-ghost"
                                to="/docs"
                            >
                                <FontAwesomeIcon icon={faBook} /> Documentation
                            </Link>
                        </div>
                    </div>
                </div>
            </section>

            <div className="container-fluid px-4 chimera-home__body">
                <section className="chimera-home__intro">
                    <div className="chimera-home__panel">
                        <h2>What CHIMERA is</h2>
                        <p>
                            CHIMERA runs a suspicious file inside a disposable
                            Windows or Linux virtual machine on the Xen
                            hypervisor and records what it does. The recording
                            is done by <strong>DRAKVUF</strong> through
                            virtual-machine introspection (VMI): it reads and
                            traps the guest&apos;s memory from the hypervisor,
                            so nothing inside the guest gives the sandbox away.
                        </p>
                        <p>
                            Every upload is also analysed statically in a
                            separate, network-less VM. When the detonation ends,
                            the behaviour and the static findings go to a
                            classifier that returns one verdict, and the
                            indicators are checked against threat-intelligence
                            sources. The console brings it all into one report.
                        </p>
                        <p className="mb-0">
                            CHIMERA builds on the open-source DRAKVUF Sandbox
                            and adds the static VM, the classifier, threat
                            intel, the Linux pipeline, mobile-app analysis,
                            network containment, guest hardening and this
                            console.
                        </p>
                    </div>
                    <div className="chimera-home__panel chimera-home__panel--perdedor">
                        <h2>PERDEDOR</h2>
                        <p>
                            The companion{" "}
                            <strong>sandbox-evasion self-test suite</strong>. It
                            asks the question malware asks first:{" "}
                            <em>does this machine look like a sandbox?</em>
                        </p>
                        <ul>
                            <li>
                                One suite, three agents: Windows (PowerShell 7),
                                Linux (Python with a small CPUID/RDTSC helper)
                                and Android (over adb), one JSON report schema.
                            </li>
                            <li>
                                Every check is tagged environment artifact,
                                timing, behavioural interaction or
                                design-specific, with a severity and a suggested
                                hardening fix.
                            </li>
                            <li>
                                Two scores: clean/applicable checks, and a 0–100
                                score weighted by severity.
                            </li>
                            <li>
                                Run against the golden image before it is used,
                                never during a real detonation.
                            </li>
                        </ul>
                        <Link to="/evasion" className="chimera-home__more">
                            Run a verification scan{" "}
                            <FontAwesomeIcon icon={faArrowRight} />
                        </Link>
                    </div>
                </section>

                <section aria-labelledby="home-pipeline">
                    <h2 id="home-pipeline" className="chimera-home__h2">
                        How an analysis flows
                    </h2>
                    <p className="chimera-home__note">
                        From upload to report. The static pass and the
                        detonation start together; the verdict waits for both.
                    </p>
                    <PipelineDiagram />
                </section>

                <section aria-labelledby="home-features">
                    <h2 id="home-features" className="chimera-home__h2">
                        Features
                    </h2>
                    <div className="chimera-home__features">
                        {FEATURES.map(([icon, title, text]) => (
                            <div key={title} className="chimera-home__feature">
                                <div
                                    className="chimera-home__feature-icon"
                                    aria-hidden="true"
                                >
                                    <FontAwesomeIcon icon={icon} />
                                </div>
                                <h3>{title}</h3>
                                <p>{text}</p>
                            </div>
                        ))}
                    </div>
                </section>

                <section aria-labelledby="home-start">
                    <h2 id="home-start" className="chimera-home__h2">
                        Read more
                    </h2>
                    <div className="chimera-home__start">
                        {START.map(([slug, title, text]) => (
                            <Link
                                key={slug}
                                to={`/docs/${slug}`}
                                className="chimera-home__start-card"
                            >
                                <span className="chimera-home__start-title">
                                    {title}{" "}
                                    <FontAwesomeIcon icon={faArrowRight} />
                                </span>
                                <span className="chimera-home__start-text">
                                    {text}
                                </span>
                            </Link>
                        ))}
                    </div>
                </section>
            </div>
        </div>
    );
}
