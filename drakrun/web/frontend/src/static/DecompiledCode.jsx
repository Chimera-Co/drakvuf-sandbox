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

const noDeep = () => Promise.resolve(null);
const LIST_LIMIT = 400;

const formatSize = (n) =>
    n >= 1024 ? `${(n / 1024).toFixed(n >= 10240 ? 0 : 1)} KiB` : `${n} B`;

// JADX's Java/Kotlin output for an APK, kept by the MobSF scan; one file is fetched at a time.
export function MobileSources({ analysisId }) {
    const state = useOptionalJson(getMobsf, analysisId);
    const [query, setQuery] = useState("");
    const [scope, setScope] = useState("app");
    const [path, setPath] = useState(null);
    const [file, setFile] = useState({});
    const [message, setMessage] = useState("");
    const sources = state.data?.sources;
    const all = useMemo(() => sources?.files || [], [sources]);
    const hasApp = all.some((f) => f.app);
    const shown = all.filter(
        (f) =>
            (scope === "all" || !hasApp || f.app) &&
            f.path.toLowerCase().includes(query.toLowerCase()),
    );
    const current = path ?? shown[0]?.path ?? null;
    useEffect(() => {
        if (!current) return undefined;
        const controller = new AbortController();
        setFile({ path: current, loading: true });
        getMobsfSource({ analysisId, path: current, signal: controller.signal })
            .then((text) => setFile({ path: current, text }))
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
                    <div className="code-pane-head">
                        <label className="w-100 small">
                            Search files
                            <input
                                className="form-control form-control-sm"
                                value={query}
                                onChange={(e) => setQuery(e.target.value)}
                            />
                        </label>
                        {hasApp ? (
                            <label className="w-100 small mt-1">
                                Show
                                <select
                                    className="form-select form-select-sm"
                                    value={scope}
                                    onChange={(e) => setScope(e.target.value)}
                                >
                                    <option value="app">App's own code</option>
                                    <option value="all">
                                        All, with libraries
                                    </option>
                                </select>
                            </label>
                        ) : null}
                    </div>
                    <ul className="code-function-list">
                        {shown.slice(0, LIST_LIMIT).map((f) => {
                            const cut = f.path.lastIndexOf("/");
                            return (
                                <li key={f.path}>
                                    <button
                                        type="button"
                                        aria-pressed={current === f.path}
                                        className={
                                            current === f.path
                                                ? "is-current"
                                                : ""
                                        }
                                        onClick={() => setPath(f.path)}
                                        title={f.path}
                                    >
                                        <span className="code-fn-name">
                                            {f.path.slice(cut + 1)}
                                        </span>
                                        <span className="code-fn-meta">
                                            {cut > 0
                                                ? f.path
                                                      .slice(0, cut)
                                                      .replaceAll("/", ".")
                                                : "(default package)"}{" "}
                                            · {formatSize(f.size)}
                                        </span>
                                    </button>
                                </li>
                            );
                        })}
                    </ul>
                    {shown.length > LIST_LIMIT ? (
                        <p className="small text-muted px-2">
                            {shown.length - LIST_LIMIT} more: refine the search.
                        </p>
                    ) : null}
                    {!shown.length ? (
                        <p className="small px-2">No files match.</p>
                    ) : null}
                </aside>
                <div className="code-pane code-main">
                    <div className="code-pane-head d-flex align-items-center gap-2">
                        <span className="font-monospace small text-break flex-grow-1">
                            {current || "No file selected"}
                        </span>
                        <span className="code-tag">
                            {language === "kotlin" ? "Kotlin" : "Java"}
                        </span>
                        <button
                            type="button"
                            className="btn btn-sm btn-outline-secondary"
                            onClick={copy}
                            disabled={!file.text}
                        >
                            Copy
                        </button>
                    </div>
                    <span className="visually-hidden" role="status">
                        {message}
                    </span>
                    <div className="code-view">
                        {file.loading ? (
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
