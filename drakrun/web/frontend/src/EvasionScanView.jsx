import { useParams } from "react-router-dom";
import { useCallback, useEffect, useRef, useState } from "react";
import { CanceledError } from "axios";
import { getScan, getScanStatus } from "./evasionApi.js";
import { isScanPending } from "./evasionStatus.js";
import { EvasionPendingView } from "./EvasionPendingView.jsx";
import { EvasionReport } from "./EvasionReport.jsx";

/**
 * Polling chain copied from AnalysisView.jsx's AnalysisViewComponent
 * (self-rescheduling setTimeout in a ref, re-armed only while pending,
 * CanceledError filtered out). The one adaptation: GET /status is
 * deliberately lightweight (no tool_results/score - see evasion_api.py), so
 * once it reports a terminal status this fetches the full record
 * (GET /scans/<id>) once, rather than assuming /status itself carries
 * everything a report needs.
 */
function EvasionScanViewComponent({ scanId }) {
    const checkInterval = useRef(null);
    const [statusInfo, setStatusInfo] = useState();
    const [scan, setScan] = useState();
    const [error, setError] = useState();

    const checkStatus = useCallback(() => {
        getScanStatus({ scanId })
            .then((response) => {
                setStatusInfo(response);
                if (isScanPending(response?.status)) {
                    if (!checkInterval.current) {
                        checkInterval.current = setTimeout(() => {
                            checkInterval.current = null;
                            checkStatus();
                        }, 1000);
                    }
                } else {
                    getScan({ scanId })
                        .then((response) => setScan(response))
                        .catch((err) => {
                            if (!(err instanceof CanceledError)) {
                                setError(err);
                                console.error(err);
                            }
                        });
                }
            })
            .catch((error) => {
                if (!(error instanceof CanceledError)) {
                    setError(error);
                    console.error(error);
                }
            });
    }, [scanId]);

    useEffect(() => {
        checkStatus();
        return () => {
            if (checkInterval.current) {
                clearTimeout(checkInterval.current);
                checkInterval.current = null;
            }
        };
    }, [scanId, checkStatus]);

    if (typeof error !== "undefined") {
        return <div className="text-danger">Error: {error.toString()}</div>;
    }

    if (typeof statusInfo === "undefined") {
        return <div>Fetching scan status...</div>;
    }

    if (isScanPending(statusInfo.status)) {
        return <EvasionPendingView status={statusInfo} />;
    }

    if (typeof scan === "undefined") {
        return <div>Finalizing verification report...</div>;
    }

    return <EvasionReport scan={scan} />;
}

export default function EvasionScanView() {
    const { scanId } = useParams();
    return (
        <div className="container-fluid px-4">
            <h1 className="m-4 h4">Sandbox evasion scan</h1>
            <EvasionScanViewComponent scanId={scanId} />
        </div>
    );
}
