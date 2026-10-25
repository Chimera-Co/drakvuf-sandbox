import { useEffect, useState } from "react";
import { ProcessTree } from "./ProcessTree.jsx";
import { useAnalysisReport } from "./AnalysisReportContext.jsx";

function baseName(path) {
    return (path || "").split(/[\\/]/).pop().toLowerCase();
}

// Expand the sample and its ancestors; unrelated branches remain collapsed.
function isProcessInteresting(process, sampleName) {
    const name = baseName(process.procname);
    return (
        sampleName !== undefined &&
        (name === sampleName || baseName(process.args?.[0]) === sampleName)
    );
}

function getProcessParents(processTree, processId) {
    let stack = processTree.map((element) => ({ parents: [], element }));
    while (stack.length > 0) {
        let { parents, element } = stack.shift();
        if (String(element.seqid) === String(processId)) {
            return parents;
        }
        if (element.children && element.children.length > 0) {
            stack = [
                ...element.children.map((child) => ({
                    parents: [...parents, element.seqid],
                    element: child,
                })),
                ...stack,
            ];
        }
    }
    return undefined;
}

function getInterestingProcesses(processTree, sampleName) {
    let activeSet = new Set();
    for (let process of processTree) {
        if (isProcessInteresting(process, sampleName)) {
            activeSet.add(process.seqid);
        }
        if (process.children.length > 0) {
            const activeChildren = getInterestingProcesses(
                process.children,
                sampleName,
            );
            if (activeChildren.size) {
                activeSet = new Set([...activeSet, ...activeChildren]);
                activeSet.add(process.seqid);
            }
        }
    }
    return activeSet;
}

export function ProcessTreeView({
    analysisId,
    sampleName,
    sampleSeqid,
    ttps = [],
    selectedProcess,
    onProcessSelect,
}) {
    const [uncollapsed, setUncollapsed] = useState(new Set());
    const [processTree, setProcessTree] = useState();
    const [error, setError] = useState();
    const [query, setQuery] = useState("");
    const { getAnalysisProcessTree } = useAnalysisReport();

    useEffect(() => {
        getAnalysisProcessTree({ analysisId })
            .then((data) => {
                setProcessTree(data);
                setUncollapsed(
                    getInterestingProcesses(
                        data,
                        sampleName ? baseName(sampleName) : undefined,
                    ),
                );
            })
            .catch((e) => {
                console.error(e);
                setError(e);
            });
    }, [analysisId, sampleName, getAnalysisProcessTree]);

    useEffect(() => {
        if (!processTree) return;
        const parents = getProcessParents(processTree, selectedProcess);
        if (parents) {
            setUncollapsed(
                (currentValue) => new Set([...currentValue, ...parents]),
            );
        }
    }, [selectedProcess, processTree]);

    useEffect(() => {
        if (!processTree || sampleSeqid == null) return;
        const parents = getProcessParents(processTree, sampleSeqid) || [];
        setUncollapsed(
            (current) => new Set([...current, ...parents, Number(sampleSeqid)]),
        );
    }, [sampleSeqid, processTree]);

    const samples = new Set(),
        lineage = new Set();
    const mark = (nodes, inherited = false) =>
        (nodes || []).forEach((node) => {
            const sample =
                String(node.seqid) === String(sampleSeqid) ||
                (!!sampleName &&
                    (baseName(node.procname) === baseName(sampleName) ||
                        baseName(node.args?.[0]) === baseName(sampleName)));
            if (sample) samples.add(node.seqid);
            if (sample || inherited) lineage.add(node.seqid);
            mark(node.children, sample || inherited);
        });
    mark(processTree);
    const filter = (nodes) =>
        (nodes || []).flatMap((node) => {
            const children = filter(node.children);
            return `${node.procname} ${node.pid}`
                .toLowerCase()
                .includes(query.toLowerCase()) || children.length
                ? [{ ...node, children: query ? children : node.children }]
                : [];
        });
    const injected = new Set(
        ttps
            .filter((ttp) => /T1055|inject/i.test(JSON.stringify(ttp)))
            .flatMap(
                (ttp) =>
                    ttp.target_process_seqids ||
                    (ttp.target_process_seqid != null
                        ? [ttp.target_process_seqid]
                        : []),
            ),
    );
    const decorate = (nodes) =>
        (nodes || []).map((node) => ({
            ...node,
            injected_into: node.injected_into || injected.has(node.seqid),
            children: decorate(node.children),
        }));
    const visible = decorate(query ? filter(processTree) : processTree);
    const allIds = (nodes) =>
        (nodes || []).flatMap((n) => [n.seqid, ...allIds(n.children)]);
    return (
        <div className="card">
            <div className="card-body p-2">
                <details open>
                    <summary className="fw-semibold mb-2">Process tree</summary>
                    <input
                        aria-label="Search process name or PID"
                        placeholder="Search name / PID"
                        className="form-control form-control-sm mb-2"
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                    />
                    {typeof processTree === "undefined" ? (
                        <span>Loading process tree...</span>
                    ) : (
                        []
                    )}
                    {typeof error !== "undefined" ? (
                        <span className="text-danger">
                            Unable to load process tree
                        </span>
                    ) : (
                        []
                    )}
                    {typeof processTree !== "undefined" ? (
                        <ProcessTree
                            processTree={visible}
                            samples={samples}
                            lineage={lineage}
                            uncollapsedSeqid={
                                query ? new Set(allIds(visible)) : uncollapsed
                            }
                            setCollapse={(seqid) => {
                                const collapse = uncollapsed.has(seqid);
                                setUncollapsed((currentValue) => {
                                    let newSet = new Set(currentValue);
                                    if (!collapse) {
                                        newSet.add(seqid);
                                    } else {
                                        newSet.delete(seqid);
                                    }
                                    return newSet;
                                });
                            }}
                            selected={selectedProcess}
                            onSelect={(seqid) => {
                                onProcessSelect(seqid);
                            }}
                        />
                    ) : (
                        []
                    )}
                </details>
            </div>
        </div>
    );
}
