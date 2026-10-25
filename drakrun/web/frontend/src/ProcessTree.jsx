import { Fragment } from "react";

export function ProcessNode({
    node,
    onClick,
    lineage = false,
    sample = false,
}) {
    return (
        <button
            className={`btn btn-sm btn-inline-link text-start text-break ${lineage ? "fw-bold text-primary" : ""}`}
            onClick={onClick}
            title={
                Array.isArray(node.args) ? node.args.join(" ") : node.args || ""
            }
        >
            {(node.procname || "unknown").split(/[\\/]/).pop()}{" "}
            <span className="font-monospace">({node.pid})</span>
            {sample && <span className="badge bg-primary ms-1">sample</span>}
            {lineage && !sample && (
                <span className="badge bg-info text-dark ms-1">descendant</span>
            )}
            {node.killed_by != null ? (
                <span className="badge bg-danger ms-1">killed</span>
            ) : node.ts_to != null ? (
                <span className="badge bg-secondary ms-1">terminated</span>
            ) : null}
            {node.injected_into && (
                <span className="badge bg-warning text-dark ms-1">
                    injected into
                </span>
            )}
            {node.exit_code != null && Number(node.exit_code) !== 0 && (
                <span className="badge bg-warning text-dark ms-1">
                    exit {node.exit_code_str || node.exit_code}
                </span>
            )}
        </button>
    );
}
export function ProcessTree({
    processTree,
    uncollapsedSeqid,
    setCollapse,
    selected,
    onSelect = () => {},
    lineage = new Set(),
    samples = new Set(),
}) {
    return (
        <ul className="list-unstyled ps-2" role="group">
            {processTree.slice(0, 250).map((element) => {
                const children = element.children || [],
                    collapsed = !uncollapsedSeqid.has(element.seqid);
                return (
                    <Fragment key={element.seqid}>
                        <li
                            className={
                                String(element.seqid) === String(selected)
                                    ? "selected border-start border-primary border-3"
                                    : ""
                            }
                        >
                            <div className="d-flex align-items-start">
                                {children.length > 0 && (
                                    <button
                                        className="btn btn-sm p-1"
                                        aria-label={`${collapsed ? "Expand" : "Collapse"} ${element.procname?.split(/[\\/]/).pop()}`}
                                        aria-expanded={!collapsed}
                                        onClick={() =>
                                            setCollapse(element.seqid)
                                        }
                                    >
                                        {collapsed ? "+" : "−"}
                                    </button>
                                )}
                                <ProcessNode
                                    node={element}
                                    onClick={() => onSelect(element.seqid)}
                                    lineage={lineage.has(element.seqid)}
                                    sample={samples.has(element.seqid)}
                                />
                            </div>
                            {!collapsed && children.length > 0 && (
                                <ProcessTree
                                    processTree={children}
                                    {...{
                                        uncollapsedSeqid,
                                        setCollapse,
                                        selected,
                                        onSelect,
                                        lineage,
                                        samples,
                                    }}
                                />
                            )}
                        </li>
                    </Fragment>
                );
            })}
        </ul>
    );
}
