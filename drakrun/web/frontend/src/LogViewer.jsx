import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { LazyLog } from "@melloware/react-logviewer";

const DEFAULT_CHUNK_SIZE = 300 * 1024;

export async function* _logLoader({ getLogEntries, chunkSize }) {
    let currentStart = 0;
    while (1) {
        try {
            const data = await getLogEntries({
                rangeStart: currentStart,
                rangeEnd: currentStart + (chunkSize - 1),
            });
            if (!data.length) return;
            const byteLength = new TextEncoder().encode(data).length;
            yield data;
            currentStart += byteLength;
            if (byteLength < chunkSize) return;
        } catch (err) {
            if (err.status === 416 || err.response?.status === 416) {
                break;
            } else {
                throw err;
            }
        }
    }
}

class ClosableLogLoader {
    constructor({ getLogEntries, chunkSize }) {
        this._logLoader = _logLoader({ getLogEntries, chunkSize });
        this._closed = false;
    }

    async next() {
        if (this._closed) {
            throw new Error("Log loader is closed");
        }
        const result = await this._logLoader.next();
        if (this._closed) {
            throw new Error("Log loader is closed");
        }
        return result;
    }

    close() {
        this._closed = true;
    }
}

export function getLogLoader({
    getLogEntries,
    chunkSize = DEFAULT_CHUNK_SIZE,
}) {
    return new ClosableLogLoader({ getLogEntries, chunkSize });
}

export function LogViewer({ logLoaderFactory }) {
    const [loading, setLoading] = useState(true);
    const [content, setContent] = useState("");
    const logLoader = useMemo(() => logLoaderFactory(), [logLoaderFactory]);
    const logViewer = useRef(null);
    const [jsonInspectedLine, setJsonInspectedLine] = useState(null);

    const loaderRef = useRef(null);

    const inspectLine = useCallback((line) => {
        try {
            const data = JSON.parse(line.trimEnd());
            setJsonInspectedLine(JSON.stringify(data, null, 4));
        } catch (err) {
            setJsonInspectedLine(null);
        }
    }, []);

    const loadNext = useCallback(() => {
        setLoading(true);
        logLoader
            .next()
            .then(({ done, value }) => {
                if (!done) {
                    setContent((content) =>
                        (content + value).slice(-8 * 1024 * 1024),
                    );
                }
                setLoading(false);
            })
            .catch((reason) => {
                if (reason?.message === "Log loader is closed") {
                    return undefined;
                }
                setLoading(false);
                console.error(reason);
            });
    }, [logLoader]);

    useEffect(() => {
        // I can't use finalization function here because useEffect
        // is triggered also on initial render. I need to explicitly
        // check if the logLoader changed. If yes, we need to invalidate
        // the previous logLoader to prevent race condition.
        if (loaderRef.current !== logLoader) {
            if (loaderRef.current) loaderRef.current.close();
            loaderRef.current = logLoader;
        }
        setContent(" ");
        setLoading(false);
        loadNext();
    }, [logLoader]);

    return (
        <>
            <p className="small text-muted">
                Raw viewer retains the most recent 8 MiB of loaded text.
            </p>
            <div style={{ height: "600px" }} className="flex-grow-1">
                <LazyLog
                    ref={logViewer}
                    loading={loading}
                    text={content}
                    onScroll={async ({
                        scrollHeight,
                        scrollTop,
                        clientHeight,
                    }) => {
                        if (
                            scrollHeight - scrollTop < clientHeight + 16 &&
                            !loading
                        ) {
                            loadNext();
                        }
                    }}
                    onLineContentClick={(event) => {
                        inspectLine(event.target?.textContent);
                    }}
                    selectableLines
                    enableSearch
                    wrapLines
                />
            </div>
            <div>
                {jsonInspectedLine ? (
                    <div>
                        <div
                            className="fw-bold"
                            style={{ borderTop: "black 1px solid" }}
                        >
                            JSON inspector
                        </div>
                        <pre>{jsonInspectedLine}</pre>
                    </div>
                ) : (
                    []
                )}
            </div>
        </>
    );
}
