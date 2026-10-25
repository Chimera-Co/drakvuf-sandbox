import { useEffect, useState } from "react";
import axios from "axios";
import { useAnalysisReport } from "./AnalysisReportContext.jsx";

export function ScreenshotFilmstrip({ images, getURL }) {
    const [index, setIndex] = useState(0),
        [playing, setPlaying] = useState(false),
        [page, setPage] = useState(0);
    const count = images.length;
    useEffect(() => {
        setIndex(0);
        setPage(0);
    }, [count]);
    const move = (amount) => setIndex((old) => (old + amount + count) % count);
    useEffect(() => {
        if (!playing || !count) return;
        const timer = setInterval(
            () => setIndex((old) => (old + 1) % count),
            1500,
        );
        return () => clearInterval(timer);
    }, [playing, count]);
    useEffect(() => {
        setPage(Math.floor(index / 40));
    }, [index]);
    if (!count) return <p>No screenshots available.</p>;
    const first = Number(images[0].timestamp);
    const offset = (image) =>
        Number.isFinite(first) && Number.isFinite(Number(image.timestamp))
            ? `+${(Number(image.timestamp) - first).toFixed(1)}s`
            : `Frame ${image.index}`;
    const image = images[index] || images[0];
    return (
        <section
            aria-label="Screenshot viewer"
            tabIndex={0}
            onKeyDown={(e) => {
                if (e.key === "ArrowLeft") {
                    e.preventDefault();
                    move(-1);
                }
                if (e.key === "ArrowRight") {
                    e.preventDefault();
                    move(1);
                }
            }}
        >
            <div className="d-flex gap-2 mb-2">
                <button
                    className="btn btn-sm btn-outline-secondary"
                    onClick={() => move(-1)}
                    aria-label="Previous screenshot"
                >
                    Previous
                </button>
                <button
                    className="btn btn-sm btn-primary"
                    onClick={() => setPlaying(!playing)}
                >
                    {playing ? "Pause" : "Play"}
                </button>
                <button
                    className="btn btn-sm btn-outline-secondary"
                    onClick={() => move(1)}
                    aria-label="Next screenshot"
                >
                    Next
                </button>
                <span>
                    {offset(image)} · {index + 1}/{count}
                </span>
                <a
                    className="ms-auto btn btn-sm btn-outline-primary"
                    href={getURL(image.index)}
                    download
                >
                    Download screenshot
                </a>
            </div>
            <div className="analysis-screenshot-stage">
                <img
                    src={getURL(image.index)}
                    alt={`screenshot-${image.index}`}
                    className="img-fluid"
                />
            </div>
            <div
                className="d-flex gap-2 overflow-auto my-3"
                aria-label="Screenshot filmstrip"
            >
                {images.slice(page * 40, page * 40 + 40).map((entry, i) => (
                    <button
                        key={entry.index}
                        className={`btn p-1 ${page * 40 + i === index ? "btn-primary" : "btn-outline-secondary"}`}
                        aria-label={`Open screenshot ${entry.index}`}
                        aria-pressed={page * 40 + i === index}
                        onClick={() => setIndex(page * 40 + i)}
                    >
                        <img
                            loading="lazy"
                            width={120}
                            src={getURL(entry.index)}
                            alt={`Thumbnail ${entry.index}`}
                        />
                        <div className="small">{offset(entry)}</div>
                    </button>
                ))}
            </div>
            {count > 40 && (
                <div>
                    <button disabled={!page} onClick={() => setPage(page - 1)}>
                        Earlier frames
                    </button>
                    <button
                        disabled={(page + 1) * 40 >= count}
                        onClick={() => setPage(page + 1)}
                    >
                        Later frames
                    </button>
                </div>
            )}
        </section>
    );
}
export function AnalysisScreenshotViewer({ analysis }) {
    const { getScreenshotURL, isOffline } = useAnalysisReport();
    const [metadata, setMetadata] = useState(null);
    useEffect(() => {
        setMetadata(null);
        if (isOffline) return;
        const controller = new AbortController();
        axios
            .get(`/files/${analysis.id}/download`, {
                params: { filename: "screenshots.json" },
                headers: { Range: "bytes=0-262143" },
                responseType: "text",
                signal: controller.signal,
            })
            .then((r) => {
                const rows = String(r.data)
                    .split("\n")
                    .filter(Boolean)
                    .flatMap((line) => {
                        try {
                            return [JSON.parse(line)];
                        } catch {
                            return [];
                        }
                    });
                if (rows.length) setMetadata(rows);
            })
            .catch(() => {});
        return () => controller.abort();
    }, [analysis.id, isOffline]);
    const images =
        metadata ||
        Array.from({ length: analysis.screenshots || 0 }, (_, i) => ({
            index: i + 1,
        }));
    return (
        <ScreenshotFilmstrip
            images={images}
            getURL={(index) => getScreenshotURL(analysis.id, index)}
        />
    );
}
