import { useEffect, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
    faCheck,
    faCircleNotch,
    faClock,
    faEllipsis,
    faMinus,
    faXmark,
} from "@fortawesome/free-solid-svg-icons";
import { getPipeline } from "./api.js";

const ICON = {
    done: faCheck,
    running: faCircleNotch,
    queued: faClock,
    failed: faXmark,
    skipped: faMinus,
    pending: faEllipsis,
};
const STATE_TEXT = {
    done: "done",
    running: "running",
    queued: "queued",
    failed: "failed",
    skipped: "skipped",
    pending: "waiting",
};
// Stop polling after this long even if a stage never finishes (a lost job must not poll forever).
const POLL_FOR_MS = 45 * 60 * 1000;

export function usePipeline(analysisId) {
    const [data, setData] = useState(null);
    useEffect(() => {
        let active = true;
        let timer;
        const started = Date.now();
        const again = (delay) => {
            if (active && Date.now() - started < POLL_FOR_MS)
                timer = setTimeout(load, delay);
        };
        function load() {
            Promise.resolve()
                .then(() => getPipeline({ analysisId }))
                .then((result) => {
                    if (!active) return;
                    setData(result);
                    if (result.active) again(4000);
                })
                .catch(() => again(10000));
        }
        load();
        return () => {
            active = false;
            clearTimeout(timer);
        };
    }, [analysisId]);
    return data;
}

// One chip per stage: upload, static, VM run, postprocessing, classifier, deep static, memory dumps, intel, report.
export function PipelineStatus({ analysisId }) {
    const data = usePipeline(analysisId);
    if (!data?.stages?.length) return null;
    return (
        <ol className="pipeline-strip" aria-label="Analysis stages">
            {data.stages.map((stage) => (
                <li
                    key={stage.id}
                    className={`pipeline-step is-${stage.state}`}
                    title={
                        stage.detail
                            ? `${stage.label}: ${STATE_TEXT[stage.state] || stage.state} (${stage.detail})`
                            : `${stage.label}: ${STATE_TEXT[stage.state] || stage.state}`
                    }
                >
                    <FontAwesomeIcon
                        icon={ICON[stage.state] || faEllipsis}
                        className="pipeline-icon"
                        spin={stage.state === "running"}
                    />
                    <span>{stage.label}</span>
                    <span className="visually-hidden">
                        : {STATE_TEXT[stage.state] || stage.state}
                    </span>
                    {stage.detail &&
                    !["pending", "queued"].includes(stage.state) ? (
                        <span className="pipeline-detail">{stage.detail}</span>
                    ) : null}
                </li>
            ))}
        </ol>
    );
}
