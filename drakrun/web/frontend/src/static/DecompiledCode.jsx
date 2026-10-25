import { useEffect, useMemo, useState } from "react";
import { CodeExplorer, SourceCode } from "./CodeExplorer.jsx";
import {
    getDeepStatic,
    getMobsf,
    getMobsfSource,
    getStaticReport,
} from "../api.js";
import { useOptionalJson } from "../AnalysisVerdict.jsx";
import "./static.css";
import { FileTree, buildFileTree } from "./FileTree.jsx";

const noDeep = () => Promise.resolve(null);

const formatSize = (n) =>
    n >= 1024 ? `${(n / 1024).toFixed(n >= 10240 ? 0 : 1)} KiB` : `${n} B`;

// JADX's Java/Kotlin output for an APK, kept by the MobSF scan; one file is fetched at a time.
export function MobileSources({ analysisId }) {
    const state = useOptionalJson(getMobsf, analysisId);
    const [tabs, setTabs] = useState(null);
    const [reveal, setReveal] = useState(null);
    const [path, setPath] = useState(null);
    const [file, setFile] = useState({});
    const [message, setMessage] = useState("");
    const sources = state.data?.sources;
    const all = useMemo(() => sources?.files || [], [sources]);
    const current =
        path ??
        (tabs?.length === 0
            ? null
            : (all.find((f) => f.app) || all[0])?.path) ??
        null;
    const openTabs = tabs ?? (current ? [current] : []);
    const open = (next) => {
        setPath(next);
        setTabs((old) => [...new Set([...(old ?? openTabs), next])].slice(-12));
    };
    const tree = useMemo(() => {
        const nodes = buildFileTree(
            all.map((f) => ({ ...f, meta: formatSize(f.size) })),
        );
        const packagePath = sources?.package?.replaceAll(".", "/");
        const mark = (items) =>
            items.forEach((node) => {
                if (node.id === packagePath)
                    node.badges = <span className="code-tag">App code</span>;
                if (node.children) mark(node.children);
            });
        mark(nodes);
        return nodes;
    }, [all, sources?.package]);
    const appFolders = all
        .filter((f) => f.app)
        .flatMap((f) =>
            f.path
                .split("/")
                .slice(0, -1)
                .map((_, i) =>
                    f.path
                        .split("/")
                        .slice(0, i + 1)
                        .join("/"),
                ),
        );
    useEffect(() => {
        if (!current) return undefined;
        const controller = new AbortController();
        setFile({ path: current, loading: true });
        getMobsfSource({ analysisId, path: current, signal: controller.signal })
            .then((text) => {
                if (!controller.signal.aborted)
                    setFile({ path: current, text });
            })
            .catch((error) => {
                if (!controller.signal.aborted)
                    setFile({ path: current, error: String(error) });
            });
        return () => controller.abort();
    }, [analysisId, current]);
    if (state.loading) return <div role="status">Loading decompiled code…</div>;
    if (state.missing)
        return (
            <div role="status" className="small text-muted">
                {state.polling
                    ? "MobSF has not finished yet: the decompiled code appears when its scan ends (this updates by itself)."
                    : "No MobSF scan for this app, so there is no decompiled code."}
            </div>
        );
    if (state.error)
        return <div role="status">Error: {String(state.error)}</div>;
    if (state.data?.error)
        return (
            <div className="alert alert-warning small">
                MobSF scan failed, so there is no decompiled code:{" "}
                {state.data.error}
            </div>
        );
    if (!all.length)
        return (
            <p className="small text-muted">
                {sources
                    ? "JADX produced no Java or Kotlin source for this app."
                    : "This scan ran before decompiled code was kept: re-run the analysis to read the code here."}
            </p>
        );
    const language = current?.endsWith(".kt") ? "kotlin" : "java";
    const copy = async () => {
        try {
            await navigator.clipboard.writeText(file.text || "");
            setMessage("Copied code");
        } catch {
            setMessage("Copy unavailable; select the source manually.");
        }
    };
    return (
        <section aria-label="Decompiled code">
            <p className="small text-muted">
                JADX (in MobSF, no network) · {all.length} files
                {sources.found > all.length ? ` of ${sources.found}` : ""}
                {sources.package ? ` · app package ${sources.package}` : ""}
                {sources.truncated
                    ? " · libraries and very large files were left out to keep the archive bounded"
                    : ""}
                . Decompiled code is an approximation of the original source.
            </p>
            <div className="code-ide is-sources">
                <aside
                    className="code-pane code-functions"
                    aria-label="Source files"
                >
                    <FileTree
                        nodes={tree}
                        label="Explorer"
                        filterLabel="Search files"
                        selected={current}
                        defaultExpanded={appFolders}
                        reveal={reveal}
                        onOpen={(node) => open(node.path)}
                    />
                </aside>
                <div className="code-pane code-main">
                    <div
                        className="code-tabs"
                        role="tablist"
                        aria-label="Open files"
                    >
                        {openTabs.map((tab) => (
                            <div className="code-tab" key={tab}>
                                <button
                                    role="tab"
                                    aria-selected={tab === current}
                                    onClick={() => open(tab)}
                                >
                                    {tab.split("/").at(-1)}
                                </button>
                                <button
                                    aria-label={`Close ${tab}`}
                                    onClick={() => {
                                        const rest = openTabs.filter(
                                            (p) => p !== tab,
                                        );
                                        setTabs(rest);
                                        if (current === tab)
                                            setPath(rest.at(-1) || null);
                                    }}
                                >
                                    ×
                                </button>
                            </div>
                        ))}
                    </div>
                    <div className="code-pane-head d-flex align-items-center gap-2">
                        <span className="font-monospace small text-break flex-grow-1">
                            {current
                                ? current.split("/").map((part, i, parts) => (
                                      <span key={i}>
                                          {i > 0 && " / "}
                                          <button
                                              className="btn btn-link btn-sm p-0"
                                              onClick={() =>
                                                  setReveal({
                                                      path: parts
                                                          .slice(0, i + 1)
                                                          .join("/"),
                                                  })
                                              }
                                          >
                                              {part}
                                          </button>
                                      </span>
                                  ))
                                : "No file selected"}
                        </span>
                        <span className="code-tag">
                            {language === "kotlin" ? "Kotlin" : "Java"}
                        </span>
                        <button
                            type="button"
                            className="btn btn-sm btn-outline-secondary"
                            onClick={copy}
                            disabled={!current || !file.text}
                        >
                            Copy
                        </button>
                    </div>
                    <span className="visually-hidden" role="status">
                        {message}
                    </span>
                    <div className="code-view">
                        {!current ? (
                            <p className="p-2">No file selected.</p>
                        ) : file.loading ? (
                            <div role="status" className="p-2 small">
                                Loading {file.path}…
                            </div>
                        ) : file.error ? (
                            <div role="status" className="p-2 small">
                                Error: {file.error}
                            </div>
                        ) : file.text != null ? (
                            <SourceCode
                                code={file.text}
                                language={language}
                                label={`Decompiled ${current}`}
                                maxBytes={1048576}
                                maxLines={20000}
                            />
                        ) : null}
                    </div>
                </div>
            </div>
        </section>
    );
}

// The decompiled functions (Ghidra, from the deep static pass) on their own report tab, so an analyst
// does not have to find them under Static analysis. Scripts show their highlighted source instead.
function Body({ data, analysisId }) {
    const format = data.type?.format;
    if (format === "apk") return <MobileSources analysisId={analysisId} />;
    if (format === "ipa")
        return (
            <p className="small text-muted">
                iOS apps ship as compiled native code (Mach-O), and MobSF does
                not decompile them on Linux: read its binary findings under
                Static analysis, iOS (MobSF).
            </p>
        );
    return <NativeCode data={data} analysisId={analysisId} format={format} />;
}

function NativeCode({ data, analysisId, format }) {
    const deepState = useOptionalJson(
        ["pe", "elf"].includes(format) ? getDeepStatic : noDeep,
        analysisId,
    );
    if (deepState.loading)
        return <div role="status">Loading decompiled code…</div>;
    return (
        <CodeExplorer
            deep={deepState.data}
            format={format}
            source={data.source}
            filename={data.file?.name}
        />
    );
}

export function DecompiledCodeTab({ analysisId }) {
    const state = useOptionalJson(getStaticReport, analysisId);
    const message = state.loading
        ? "Loading…"
        : state.missing
          ? "No static analysis yet: code appears once the static and deep passes finish (this updates by itself)."
          : state.error
            ? `Error: ${state.error}`
            : state.data?.error
              ? `Static analysis failed: ${state.data.error}`
              : null;
    return (
        <div className="static-shell py-2">
            {message ? (
                <div role="status">{message}</div>
            ) : (
                <Body
                    key={analysisId}
                    data={state.data}
                    analysisId={analysisId}
                />
            )}
        </div>
    );
}
