import { useEffect, useState } from "react";
import axios from "axios";
import { StructuredTable } from "./StructuredLogs.jsx";

export function buildFileTree(files) {
    const root = Object.create(null);
    for (const file of files) {
        const path = typeof file === "string" ? file : file.path || file.name;
        if (!path) continue;
        const group = /\.log$|log_index|ttps.json/.test(path)
            ? "logs"
            : /\.pcap|keys|\.key$/.test(path)
              ? "network"
              : /dump/.test(path)
                ? "memory dumps"
                : /static|deep/.test(path)
                  ? "static"
                  : /report|classification|metadata/.test(path)
                    ? "reports"
                    : "files";
        const parts = [group, ...path.split(/[\\/]/).filter(Boolean)];
        let node = root;
        for (const part of parts.slice(0, -1)) {
            node[part] ||= Object.create(null);
            node = node[part];
        }
        node[parts.at(-1)] = {
            file: path,
            size: typeof file === "object" ? file.size : null,
        };
    }
    return root;
}
function Folders({ tree, onSelect, depth = 0 }) {
    const [limit, setLimit] = useState(100);
    if (depth > 16) return <p>Directory depth limit reached</p>;
    return (
        <ul className="list-unstyled ps-2">
            {Object.entries(tree)
                .slice(0, limit)
                .map(([name, node]) => (
                    <li key={name} className="text-break">
                        {typeof node.file === "string" ? (
                            <button
                                className="btn btn-sm btn-inline-link text-break text-start"
                                onClick={() => onSelect(node)}
                            >
                                {name}
                            </button>
                        ) : (
                            <details open={depth === 0}>
                                <summary>{name}</summary>
                                <Folders
                                    tree={node}
                                    onSelect={onSelect}
                                    depth={depth + 1}
                                />
                            </details>
                        )}
                    </li>
                ))}
            {Object.keys(tree).length > limit && (
                <li>
                    <button
                        className="btn btn-sm btn-outline-secondary"
                        onClick={() => setLimit(limit + 100)}
                    >
                        More files
                    </button>
                </li>
            )}
        </ul>
    );
}
export function FileExplorer({ files, analysisId }) {
    const [selected, setSelected] = useState(null),
        [preview, setPreview] = useState(null),
        [error, setError] = useState("");
    const url = selected
        ? `${axios.defaults.baseURL || "/api"}/files/${analysisId}/download?filename=${encodeURIComponent(selected.file)}`
        : "";
    useEffect(() => {
        setPreview(null);
        setError("");
        if (!selected) return;
        const controller = new AbortController();
        const ext = selected.file.split(".").pop().toLowerCase();
        if (
            ![
                "json",
                "jsonl",
                "log",
                "txt",
                "csv",
                "xml",
                "yaml",
                "yml",
                "png",
            ].includes(ext)
        )
            return;
        axios
            .get(`/files/${analysisId}/download`, {
                params: { filename: selected.file },
                headers: { Range: "bytes=0-262143" },
                responseType: "arraybuffer",
                signal: controller.signal,
            })
            .then((r) => {
                const bytes = new Uint8Array(r.data).slice(0, 262144),
                    range = r.headers?.["content-range"],
                    size = range ? Number(range.split("/")[1]) : bytes.length;
                if (ext === "png") {
                    if (size > 262144) {
                        setError(
                            "Image exceeds preview limit; download to view.",
                        );
                        return;
                    }
                    const magic = [137, 80, 78, 71, 13, 10, 26, 10];
                    if (!magic.every((n, i) => bytes[i] === n)) {
                        setError("Invalid PNG header.");
                        return;
                    }
                    setPreview({
                        image: URL.createObjectURL(
                            new Blob([bytes], { type: "image/png" }),
                        ),
                        size,
                    });
                    return;
                }
                const text = new TextDecoder().decode(bytes);
                let value = text;
                if (ext === "json") {
                    try {
                        value = JSON.stringify(JSON.parse(text), null, 2);
                    } catch {}
                }
                const parts = text.split("\n");
                if (size > bytes.length) parts.pop();
                const rows = ["log", "jsonl"].includes(ext)
                    ? parts
                          .filter(Boolean)
                          .slice(0, 1000)
                          .map((line) => {
                              try {
                                  return JSON.parse(line);
                              } catch {
                                  return { Text: line };
                              }
                          })
                    : null;
                setPreview({
                    text: value,
                    rows,
                    size,
                    truncated: size > bytes.length,
                });
            })
            .catch((e) => {
                if (!controller.signal.aborted)
                    setError(
                        e.response?.status === 416
                            ? "Empty file."
                            : "Preview unavailable.",
                    );
            });
        return () => controller.abort();
    }, [selected, analysisId]);
    useEffect(
        () => () => {
            if (preview?.image) URL.revokeObjectURL(preview.image);
        },
        [preview],
    );
    return (
        <div className="analysis-explorer">
            <aside aria-label="Analysis folders">
                <Folders tree={buildFileTree(files)} onSelect={setSelected} />
            </aside>
            <section aria-label="File preview" className="min-width-0">
                {selected ? (
                    <>
                        <h6 className="text-break font-monospace">
                            {selected.file}
                        </h6>
                        <p className="small">
                            Type: {selected.file.split(".").pop()} · Size:{" "}
                            {selected.size ?? preview?.size ?? "not reported"}{" "}
                            bytes
                        </p>
                        <a
                            className="btn btn-sm btn-primary mb-3"
                            href={url}
                            download
                        >
                            Download file
                        </a>
                        <p className="small text-muted">
                            Preview limited to the first 256 KiB.
                        </p>
                        {error && <p role="status">{error}</p>}
                        {preview?.truncated && (
                            <p className="text-warning-emphasis">
                                Preview truncated.
                            </p>
                        )}
                        {preview?.image ? (
                            <img
                                className="img-fluid"
                                alt={selected.file}
                                src={preview.image}
                            />
                        ) : preview?.rows ? (
                            <StructuredTable
                                rows={preview.rows}
                                logType={selected.file
                                    .split(/[\\/]/)
                                    .pop()
                                    .replace(/\.(log|jsonl)$/i, "")}
                            />
                        ) : preview?.text != null ? (
                            <pre
                                className="text-break"
                                style={{
                                    whiteSpace: "pre-wrap",
                                    maxHeight: 650,
                                    overflow: "auto",
                                }}
                            >
                                {preview.text}
                            </pre>
                        ) : !error ? (
                            <p>Download this file to inspect it.</p>
                        ) : null}
                    </>
                ) : (
                    <p>Select a file to preview its contents.</p>
                )}
            </section>
        </div>
    );
}
