import { ThreatIntelCard } from "./ThreatIntelCard.jsx";
import MemoryDumps from "./MemoryDumps.jsx";
import { AnalysisDashboard, ProcessWorkspace } from "./AnalysisDashboard.jsx";
import { LogWorkspace } from "./StructuredLogs.jsx";
import "./AnalysisWorkspace.css";
import { useCallback, useEffect, useState } from "react";
import { getLog, getLogList, getProcessLog } from "./api.js";
import { TabSwitcher, Tab, useTabContext } from "./TabSwitcher.jsx";
import { getLogLoader, LogViewer } from "./LogViewer.jsx";
import { AnalysisMetadataTable } from "./AnalysisMetadataTable.jsx";
import { AnalysisScreenshotViewer } from "./AnalysisScreenshotViewer.jsx";
import { ProcessTreeView } from "./ProcessTreeView.jsx";
import { MethodFilterPicker } from "./MethodFilterPicker.jsx";
import { ProcessInfoTable } from "./ProcessInfoTable.jsx";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faDownload, faFileLines } from "@fortawesome/free-solid-svg-icons";
import axios, { CanceledError } from "axios";
import { AnalysisSummary } from "./AnalysisSummary.jsx";
import { ProcessBadge } from "./ProcessBadge.jsx";
import { AnalysisFilesViewer } from "./AnalysisFiles.jsx";
import { useAnalysisReport } from "./AnalysisReportContext.jsx";
import { StaticAnalysisTab, VerdictCard } from "./AnalysisVerdict.jsx";

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
                    <TabSwitcher activeTab="Static analysis">
                        <PaddedTab tab="Static analysis">
                            <StaticAnalysisTab analysisId={analysis.id} />
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

export function AnalysisReport() {
    const [selectedProcess, setSelectedProcess] = useState();
    const [activeReportTab, setActiveReportTab] = useState();
    const [analysisSummary, setAnalysisSummary] = useState();
    const {
        analysisInfo: analysis,
        getAnalysisSummary,
        isOffline,
    } = useAnalysisReport();
    const isStatic = analysis.options?.mode === "static-only";
    const plugins = analysis.options?.plugins;
    const baseUrl = axios.defaults.baseURL;
    const analysisId = analysis.id;

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
        },
        [setSelectedProcess, setActiveReportTab],
    );

    return (
        <>
            <div
                className={`analysis-workspace ${isStatic ? "analysis-static-only" : ""}`}
            >
                {!isStatic && (
                    <aside className="analysis-process-column">
                        <ProcessTreeView
                            analysisId={analysis.id}
                            sampleName={analysis.options?.sample_filename}
                            sampleSeqid={analysisSummary?.startup?.process}
                            ttps={analysisSummary?.ttps}
                            selectedProcess={selectedProcess}
                            onProcessSelect={onSelectProcess}
                        />
                    </aside>
                )}
                <div className="analysis-main-column">
                    {!isOffline ? (
                        <VerdictCard analysisId={analysis.id} />
                    ) : null}
                    <ThreatIntelCard
                        analysisId={analysis.id}
                        isOffline={isOffline}
                    />
                    <details className="mb-2">
                        <summary>Analysis metadata</summary>
                        <AnalysisMetadataTable analysis={analysis} />
                    </details>
                    {!isOffline ? (
                        <div className="card">
                            <div className="card-body">
                                <a href={`${baseUrl}/pcap_file/${analysis.id}`}>
                                    <button className="btn btn-primary m-1">
                                        <FontAwesomeIcon
                                            icon={faDownload}
                                            className="me-2"
                                        />
                                        Download PCAP
                                    </button>
                                </a>
                                {Array.isArray(plugins) &&
                                plugins.includes("tlsmon") ? (
                                    <a
                                        href={`${baseUrl}/pcap_keys/${analysis.id}`}
                                    >
                                        <button className="btn btn-primary m-1">
                                            <FontAwesomeIcon
                                                icon={faDownload}
                                                className="me-2"
                                            />
                                            TLS keys
                                        </button>
                                    </a>
                                ) : (
                                    []
                                )}
                                {Array.isArray(plugins) &&
                                plugins.includes("memdump") ? (
                                    <a href={`${baseUrl}/dumps/${analysis.id}`}>
                                        <button className="btn btn-primary m-1">
                                            <FontAwesomeIcon
                                                icon={faDownload}
                                                className="me-2"
                                            />
                                            Memory dumps
                                        </button>
                                    </a>
                                ) : (
                                    []
                                )}
                                {!isStatic && analysis["html_report"] ? (
                                    <a href={`${baseUrl}/html/${analysis.id}`}>
                                        <button className="btn btn-primary m-1">
                                            <FontAwesomeIcon
                                                icon={faDownload}
                                                className="me-2"
                                            />
                                            HTML report
                                        </button>
                                    </a>
                                ) : (
                                    []
                                )}
                                {analysis["chimera_report"] ? (
                                    <a
                                        href={`${baseUrl}/chimera_report/${analysis.id}/html`}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                    >
                                        <button className="btn btn-primary m-1">
                                            <FontAwesomeIcon
                                                icon={faFileLines}
                                                className="me-2"
                                            />
                                            Printable report
                                        </button>
                                    </a>
                                ) : (
                                    []
                                )}
                                {analysis["chimera_report"]
                                    ? ["csv", "json"].map((format) => (
                                          <a
                                              key={format}
                                              href={`${baseUrl}/chimera_report/${analysis.id}/iocs.${format}`}
                                          >
                                              <button className="btn btn-outline-primary m-1">
                                                  <FontAwesomeIcon
                                                      icon={faDownload}
                                                      className="me-2"
                                                  />
                                                  IOCs ({format.toUpperCase()})
                                              </button>
                                          </a>
                                      ))
                                    : []}
                            </div>
                        </div>
                    ) : (
                        []
                    )}
                    <AnalysisReportTabs
                        analysis={analysis}
                        analysisSummary={analysisSummary}
                        selectedProcess={selectedProcess}
                        setSelectedProcess={onSelectProcess}
                        onFilterProcess={setSelectedProcess}
                        activeReportTab={activeReportTab}
                        setActiveReportTab={setActiveReportTab}
                        isOffline={isOffline}
                    />
                </div>
            </div>
        </>
    );
}
