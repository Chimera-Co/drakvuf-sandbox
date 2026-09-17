import { AnalysisStatusBadge } from "./AnalysisStatusBadge.jsx";
import { AnalysisPendingStatusBox } from "./AnalysisPendingView.jsx";

/**
 * Reuses AnalysisPendingStatusBox/AnalysisStatusBadge verbatim - a scan's
 * status/substatus vocabulary (queued/started/.../preparing_vm/running/...)
 * is the same shape analyses already use, so no separate pending-status
 * component is needed.
 */
export function EvasionPendingView({ status }) {
    return (
        <div className="row">
            <div className="col">
                <AnalysisPendingStatusBox>
                    <div>
                        Please wait until the verification scan is completed...
                    </div>
                    <div>
                        <div className="me-2 py-2 d-inline-block">
                            Current status:
                        </div>
                        <AnalysisStatusBadge
                            status={status.status}
                            substatus={status.substatus}
                        />
                    </div>
                    {typeof status.vm_id === "number" ? (
                        <div className="text-muted small">
                            Running on vm-{status.vm_id}
                        </div>
                    ) : (
                        []
                    )}
                </AnalysisPendingStatusBox>
            </div>
        </div>
    );
}
