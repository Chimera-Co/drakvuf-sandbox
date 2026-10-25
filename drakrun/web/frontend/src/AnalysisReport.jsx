import { ThreatIntelCard } from "./ThreatIntelCard.jsx";
import MemoryDumps from "./MemoryDumps.jsx";
import { AnalysisDashboard, ProcessWorkspace } from "./AnalysisDashboard.jsx";
import { LogWorkspace } from "./StructuredLogs.jsx";
import "./AnalysisWorkspace.css";
import { useCallback, useEffect, useRef, useState } from "react";
import { getChimeraReport, getLog, getLogList, getProcessLog } from "./api.js";
import { TabSwitcher, Tab, useTabContext } from "./TabSwitcher.jsx";
import { getLogLoader, LogViewer } from "./LogViewer.jsx";
import { AnalysisMetadataTable } from "./AnalysisMetadataTable.jsx";
import { AnalysisScreenshotViewer } from "./AnalysisScreenshotViewer.jsx";
import { ProcessTreeView } from "./ProcessTreeView.jsx";
import { MethodFilterPicker } from "./MethodFilterPicker.jsx";
import { ProcessInfoTable } from "./ProcessInfoTable.jsx";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
    faDownload,
    faFileLines,
    faSitemap,
} from "@fortawesome/free-solid-svg-icons";
import axios, { CanceledError } from "axios";
import { AnalysisSummary } from "./AnalysisSummary.jsx";
import { ProcessBadge } from "./ProcessBadge.jsx";
import { AnalysisFilesViewer } from "./AnalysisFiles.jsx";
import { useAnalysisReport } from "./AnalysisReportContext.jsx";
import { StaticAnalysisTab, VerdictCard } from "./AnalysisVerdict.jsx";
import { DecompiledCodeTab } from "./static/DecompiledCode.jsx";
import { EdgeDrawer, useOutOfView } from "./EdgeDrawer.jsx";
import { PipelineStatus } from "./PipelineStatus.jsx";
import { SimpleReport } from "./SimpleReport.jsx";

export function AnalysisLogViewerTab({ analysisId }) {
    const logType = useTabContext()?.activeTab;
    const logLoaderFactory = useCallback(() => {
        return getLogLoader({
            getLogEntries: ({ rangeStart, rangeEnd }) =>
                getLog({ analysisId, logType, rangeStart, rangeEnd }),
        });
    }, [analysisId, logType]);
    if (!logType) return [];
    return <LogViewer logLoaderFactory={logLoaderFactory} />;
}

function AnalysisLogViewer({ analysisId }) {
    const [tabs, setTabs] = useState();
    const [activeTab, setActiveTab] = useState();
    const [error, setError] = useState();
    const loadLogTypes = useCallback(async () => {
        try {
            const logTypes = await getLogList({ analysisId });
            const tabs = logTypes
                .filter((logType) => logType.endsWith(".log"))
                .map((logType) => logType.split(".")[0]);
            setTabs(tabs);
            setActiveTab(tabs[0]);
        } catch (err) {
            setError(err);
            console.error(err);
        }
    }, [analysisId]);

    useEffect(() => {
        loadLogTypes();
    }, [analysisId]);

    if (typeof tabs === "undefined") {
        return <div className="py-2">Loading log information...</div>;
    }

    if (typeof error !== "undefined") {
        return (
            <div className="text-danger py-2">Error: {error.toString()}</div>
        );
    }

    return (
        <div>
            <div className="fw-bold py-2">Log type:</div>
            <div className="d-flex align-items-start">
                <TabSwitcher
                    tabs={tabs}
                    activeTab={activeTab}
                    onTabSwitch={setActiveTab}
                    tabClassName="flex-column nav-pills me-3"
                    contentClassName="flex-grow-1"
                >
                    <AnalysisLogViewerTab analysisId={analysisId} />
                </TabSwitcher>
            </div>
        </div>
    );
}

function ProcessInfoTab({ analysisId, selectedProcess, processInfo }) {
    const activeTab = useTabContext()?.activeTab;
    if (activeTab !== "Process information") {
        return [];
    }
    return <ProcessInfoTable processInfo={processInfo["process"]} />;
}

function ProcessLogViewerTab({ analysisId, selectedProcess, processInfo }) {
    const [methodsFilter, setMethodsFilter] = useState([]);
    const activeTab = useTabContext()?.activeTab;
    const logType =
        activeTab === "Process information" || !processInfo["logs"][activeTab]
            ? undefined
            : activeTab;
    const logMethods = logType ? processInfo["logs"][logType] : [];
    const logLoaderFactory = useCallback(() => {
        return getLogLoader({
            getLogEntries: ({ rangeStart, rangeEnd }) => {
                return getProcessLog({
                    analysisId,
                    logType,
                    selectedProcess,
                    rangeStart,
                    rangeEnd,
                    methodsFilter,
                });
            },
        });
    }, [analysisId, logType, selectedProcess, methodsFilter]);
    useEffect(() => {
        setMethodsFilter([]);
    }, [logType]);
    if (!logType) return [];
    return (
        <>
            <div>
                <label className="form-label">Method filter</label>
                <MethodFilterPicker
                    onFilterChange={setMethodsFilter}
                    currentFilter={methodsFilter}
                    methods={logMethods}
                />
            </div>
            <LogViewer logLoaderFactory={logLoaderFactory} />
        </>
    );
}

function ProcessLogViewer({ analysisId, selectedProcess }) {
    const [tabs, setTabs] = useState();
    const [activeTab, setActiveTab] = useState();
    const [processInfo, setProcessInfo] = useState();
    const [error, setError] = useState();
    const { getProcessInfo, isOffline } = useAnalysisReport();
    const loadProcessInfo = useCallback(
        async (processSeqId) => {
            try {
                const processInfo = await getProcessInfo({
                    analysisId,
                    processSeqId,
                });
                const tabs = Object.keys(processInfo["logs"]);
                setProcessInfo(processInfo);
                setTabs(["Process information", ...tabs]);
                setActiveTab("Process information");
            } catch (err) {
                setError(err);
                console.error(err);
            }
        },
        [analysisId],
    );

    useEffect(() => {
        if (typeof selectedProcess === "undefined") return;
        loadProcessInfo(selectedProcess);
    }, [analysisId, selectedProcess]);

    if (typeof selectedProcess === "undefined") {
        return (
            <div className="fw-bold py-2">
                Select a process from the process tree above
            </div>
        );
    }

    if (typeof tabs === "undefined") {
        return <div className="py-2">Loading log information...</div>;
    }

    if (typeof error !== "undefined") {
        return (
            <div className="text-danger py-2">Error: {error.toString()}</div>
        );
    }

    return (
        <div>
            <div className="fw-bold py-2">Log type:</div>
            <div className="d-flex align-items-start">
                <TabSwitcher
                    tabs={tabs}
                    activeTab={activeTab}
                    onTabSwitch={setActiveTab}
                    tabClassName="flex-column nav-pills me-3"
                    contentClassName="flex-grow-1"
                >
                    <ProcessInfoTab
                        analysisId={analysisId}
                        selectedProcess={selectedProcess}
                        processInfo={processInfo}
                    />
                    {!isOffline ? (
                        <ProcessLogViewerTab
                            analysisId={analysisId}
                            selectedProcess={selectedProcess}
                            processInfo={processInfo}
                        />
                    ) : (
                        []
                    )}
                </TabSwitcher>
            </div>
        </div>
    );
}

function PaddedTab({ tab, children }) {
    return (
        <Tab tab={tab}>
            <div className="mt-2">{children}</div>
        </Tab>
    );
}

function AnalysisReportTabs({
    analysis,
    analysisSummary,
    chimeraReport,
    selectedProcess,
    setSelectedProcess,
    onFilterProcess,
    activeReportTab,
    setActiveReportTab,
    isOffline,
}) {
    const getHeader = useCallback(
        (tab) => {
            if (tab === "Process info") {
                let process;
                if (analysisSummary?.processes && selectedProcess) {
                    process = analysisSummary.processes[selectedProcess];
                }
                if (!process) {
                    return "Process info";
                }
                return (
                    <>
                        <ProcessBadge process={process} />
                    </>
                );
            } else {
                return tab;
            }
        },
        [analysisSummary, selectedProcess],
    );
    if (analysis.options?.mode === "static-only") {
        return (
            <div className="card">
                <div className="card-body">
                    <TabSwitcher
                        activeTab={
                            activeReportTab === "Decompiled code"
                                ? "Decompiled code"
                                : "Static analysis"
                        }
                        onTabSwitch={setActiveReportTab}
                    >
                        <PaddedTab tab="Static analysis">
                            <StaticAnalysisTab analysisId={analysis.id} />
                        </PaddedTab>
                        <PaddedTab tab="Decompiled code">
                            <DecompiledCodeTab analysisId={analysis.id} />
                        </PaddedTab>
                    </TabSwitcher>
                </div>
            </div>
        );
    }
    return (
        <div className="card">
            <div className="card-body">
                <TabSwitcher
                    activeTab={activeReportTab || "Summary report"}
                    onTabSwitch={setActiveReportTab}
                    getHeader={getHeader}
                >
                    <PaddedTab tab="Summary report">
                        <AnalysisDashboard
                            analysisId={analysis.id}
                            summary={analysisSummary}
                            chimeraReport={chimeraReport}
                            onSelect={setSelectedProcess}
                            isOffline={isOffline}
                        />
                    </PaddedTab>
                    {!isOffline ? (
                        <PaddedTab tab="General logs">
                            <LogWorkspace
                                analysisId={analysis.id}
                                selectedProcess={selectedProcess}
                                onProcessSelect={setSelectedProcess}
                                processes={analysisSummary?.processes}
                                onFilterProcess={onFilterProcess}
                            />
                        </PaddedTab>
                    ) : (
                        []
                    )}
                    <PaddedTab tab="Process info">
                        {isOffline ? (
                            <ProcessLogViewer
                                analysisId={analysis.id}
                                selectedProcess={selectedProcess}
                            />
                        ) : (
                            <ProcessWorkspace
                                analysisId={analysis.id}
                                selectedProcess={selectedProcess}
                                summary={analysisSummary}
                                analysisStart={
                                    analysis.time_execution_started ||
                                    analysis.time_started
                                }
                                onSelect={setSelectedProcess}
                                isOffline={isOffline}
                            />
                        )}
                    </PaddedTab>
                    {analysis.screenshots ? (
                        <PaddedTab tab="Screenshots">
                            <AnalysisScreenshotViewer analysis={analysis} />
                        </PaddedTab>
                    ) : null}
                    {!isOffline ? (
                        <PaddedTab tab="Static analysis">
                            <StaticAnalysisTab analysisId={analysis.id} />
                        </PaddedTab>
                    ) : (
                        []
                    )}
                    {!isOffline ? (
                        <PaddedTab tab="Decompiled code">
                            <DecompiledCodeTab analysisId={analysis.id} />
                        </PaddedTab>
                    ) : (
                        []
                    )}
                    {!isOffline ? (
                        <PaddedTab tab="Memory dumps">
                            <MemoryDumps analysisId={analysis.id} />
                        </PaddedTab>
                    ) : (
                        []
                    )}
                    {!isOffline ? (
                        <PaddedTab tab="Analysis files">
                            <AnalysisFilesViewer analysisId={analysis.id} />
                        </PaddedTab>
                    ) : (
                        []
                    )}
                </TabSwitcher>
            </div>
        </div>
    );
}

const VIEW_KEY = "chimera-report-view";

function loadView() {
    try {
        return localStorage.getItem(VIEW_KEY) === "advanced"
            ? "advanced"
            : "simple";
    } catch {
        return "simple";
    }
}

// Simple (digest) or advanced (every tab), remembered in this browser.
function useReportView() {
    const [view, setViewState] = useState(loadView);
    const setView = useCallback((next) => {
        setViewState(next);
        try {
            localStorage.setItem(VIEW_KEY, next);
        } catch {
            // private window or blocked storage: the choice lasts for this visit
        }
    }, []);
    return [view, setView];
}

// chimera-report.json; it appears after postprocessing, so a 404 is retried for a while.
function useChimeraReport(analysisId, enabled) {
    const [state, setState] = useState({ status: "loading" });
    useEffect(() => {
        if (!enabled) {
            setState({ status: "off" });
            return undefined;
        }
        let active = true;
        let timer;
        let tries = 0;
        setState({ status: "loading" });
        const load = () =>
            Promise.resolve()
                .then(() => getChimeraReport({ analysisId }))
                .then((data) => active && setState({ status: "ok", data }))
                .catch((error) => {
                    if (!active) return;
                    if (error?.response?.status === 404) {
                        setState({ status: "missing" });
                        if (++tries < 120) timer = setTimeout(load, 7500);
                    } else setState({ status: "error" });
                });
        load();
        return () => {
            active = false;
            clearTimeout(timer);
        };
    }, [analysisId, enabled]);
    return state;
}

function DownloadsMenu({ analysis, isStatic }) {
    const box = useRef(null);
    const baseUrl = axios.defaults.baseURL;
    const plugins = Array.isArray(analysis.options?.plugins)
        ? analysis.options.plugins
        : [];
    useEffect(() => {
        const onDown = (e) => {
            if (box.current?.open && !box.current.contains(e.target))
                box.current.open = false;
        };
        document.addEventListener("pointerdown", onDown);
        return () => document.removeEventListener("pointerdown", onDown);
    }, []);
    const items = [
        ["PCAP", `${baseUrl}/pcap_file/${analysis.id}`, true],
        [
            "TLS keys",
            `${baseUrl}/pcap_keys/${analysis.id}`,
            plugins.includes("tlsmon"),
        ],
        [
            "Memory dumps",
            `${baseUrl}/dumps/${analysis.id}`,
            plugins.includes("memdump"),
        ],
        [
            "HTML report",
            `${baseUrl}/html/${analysis.id}`,
            !isStatic && analysis["html_report"],
        ],
        [
            "IOCs (CSV)",
            `${baseUrl}/chimera_report/${analysis.id}/iocs.csv`,
            analysis["chimera_report"],
        ],
        [
            "IOCs (JSON)",
            `${baseUrl}/chimera_report/${analysis.id}/iocs.json`,
            analysis["chimera_report"],
        ],
    ].filter(([, , shown]) => shown);
    return (
        <details className="chimera-menu" ref={box}>
            <summary className="btn btn-sm btn-outline-primary">
                <FontAwesomeIcon icon={faDownload} className="me-2" />
                Downloads
            </summary>
            <div className="chimera-menu-list">
                {items.map(([label, href]) => (
                    <a
                        key={label}
                        href={href}
                        onClick={() => {
                            if (box.current) box.current.open = false;
                        }}
                    >
                        <FontAwesomeIcon icon={faDownload} />
                        {label}
                    </a>
                ))}
            </div>
        </details>
    );
}

function formatSize(bytes) {
    if (typeof bytes !== "number") return null;
    const units = ["B", "KiB", "MiB", "GiB"];
    let value = bytes;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
        value /= 1024;
        unit += 1;
    }
    return `${value.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}

export function AnalysisReport() {
    const [selectedProcess, setSelectedProcess] = useState();
    const [activeReportTab, setActiveReportTab] = useState();
    const [analysisSummary, setAnalysisSummary] = useState();
    const [view, setView] = useReportView();
    const treeSlot = useRef(null);
    const treeOut = useOutOfView(treeSlot);
    const {
        analysisInfo: analysis,
        getAnalysisSummary,
        isOffline,
    } = useAnalysisReport();
    const isStatic = analysis.options?.mode === "static-only";
    const baseUrl = axios.defaults.baseURL;
    const analysisId = analysis.id;
    const report = useChimeraReport(analysisId, !isOffline && !isStatic);
    const simple = view === "simple" && !isStatic;

    const fetchSummary = useCallback(() => {
        getAnalysisSummary({ analysisId })
            .then((response) => {
                setAnalysisSummary(response);
            })
            .catch((error) => {
                if (!(error instanceof CanceledError)) {
                    setAnalysisSummary(null);
                    console.error(error);
                }
            });
    }, [analysisId, getAnalysisSummary]);

    useEffect(() => {
        if (!isStatic) fetchSummary();
    }, [analysisId, fetchSummary, isStatic]);

    const onSelectProcess = useCallback(
        (processId) => {
            setSelectedProcess(processId);
            setActiveReportTab("Process info");
            setView("advanced");
        },
        [setSelectedProcess, setActiveReportTab, setView],
    );

    const file = analysis.file || {};
    const name =
        file.name || analysis.options?.sample_filename || "Analysis report";
    const facts = [
        file.type,
        formatSize(file.size_bytes),
        analysis.options?.guest_os
            ? `${analysis.options.guest_os} guest`
            : null,
        isStatic ? "static only" : null,
    ].filter(Boolean);
    const tree = (
        <ProcessTreeView
            analysisId={analysis.id}
            sampleName={analysis.options?.sample_filename}
            sampleSeqid={analysisSummary?.startup?.process}
            ttps={analysisSummary?.ttps}
            selectedProcess={selectedProcess}
            onProcessSelect={onSelectProcess}
        />
    );

    return (
        <>
            <header className="report-head">
                <div className="min-width-0">
                    <h1>{name}</h1>
                    <div className="report-sub">
                        {facts.join(" · ")}
                        {file.sha256 ? (
                            <span className="d-block font-monospace">
                                SHA-256 {file.sha256}
                            </span>
                        ) : null}
                    </div>
                </div>
                <div className="report-actions">
                    {!isStatic ? (
                        <div
                            className="chimera-segmented"
                            role="group"
                            aria-label="Report view"
                        >
                            {[
                                ["simple", "Simple"],
                                ["advanced", "Advanced"],
                            ].map(([id, label]) => (
                                <button
                                    key={id}
                                    type="button"
                                    aria-pressed={view === id}
                                    onClick={() => setView(id)}
                                >
                                    {label}
                                </button>
                            ))}
                        </div>
                    ) : null}
                    {analysis["chimera_report"] ? (
                        <a
                            className="btn btn-sm btn-primary"
                            href={`${baseUrl}/chimera_report/${analysis.id}/html`}
                            target="_blank"
                            rel="noopener noreferrer"
                        >
                            <FontAwesomeIcon
                                icon={faFileLines}
                                className="me-2"
                            />
                            Printable report
                        </a>
                    ) : null}
                    {!isOffline ? (
                        <DownloadsMenu
                            analysis={analysis}
                            isStatic={isStatic}
                        />
                    ) : null}
                </div>
            </header>
            {!isOffline ? <PipelineStatus analysisId={analysis.id} /> : null}
            <div className={`analysis-overview ${isStatic ? "is-static" : ""}`}>
                {!isStatic ? (
                    <div className="analysis-tree-slot" ref={treeSlot}>
                        {tree}
                    </div>
                ) : null}
                <div className="analysis-side">
                    {!isOffline ? (
                        <VerdictCard
                            analysisId={analysis.id}
                            compact={simple}
                        />
                    ) : null}
                    <ThreatIntelCard
                        analysisId={analysis.id}
                        isOffline={isOffline}
                    />
                    {!simple ? (
                        <details>
                            <summary>Analysis metadata</summary>
                            <AnalysisMetadataTable analysis={analysis} />
                        </details>
                    ) : null}
                </div>
            </div>
            {!isStatic ? (
                <EdgeDrawer
                    side="left"
                    label="Process tree"
                    icon={faSitemap}
                    hidden={!treeOut}
                >
                    {tree}
                </EdgeDrawer>
            ) : null}
            {simple ? (
                <SimpleReport
                    analysisId={analysis.id}
                    summary={analysisSummary}
                    chimeraReport={report.data}
                    reportState={report.status}
                    onSelect={onSelectProcess}
                    onAdvanced={() => setView("advanced")}
                />
            ) : (
                <AnalysisReportTabs
                    analysis={analysis}
                    analysisSummary={analysisSummary}
                    chimeraReport={report.data}
                    selectedProcess={selectedProcess}
                    setSelectedProcess={onSelectProcess}
                    onFilterProcess={setSelectedProcess}
                    activeReportTab={activeReportTab}
                    setActiveReportTab={setActiveReportTab}
                    isOffline={isOffline}
                />
            )}
        </>
    );
}
