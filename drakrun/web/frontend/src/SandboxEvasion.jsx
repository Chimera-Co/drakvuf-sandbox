import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { CanceledError } from "axios";
import { getSandboxes, createScan } from "./evasionApi.js";
import { EvasionToolOptions } from "./EvasionToolOptions.jsx";

/**
 * Every choice on this page - which sandboxes exist, which tools are
 * available for the chosen one, and what each tool can be configured with -
 * comes straight from GET /api/evasion/sandboxes. Nothing here hardcodes a
 * platform, a sandbox name, or a tool id: a Linux sandbox with no supported
 * tools yet simply renders an empty tool list, and a future third verifier
 * shows up automatically because this component only ever iterates over
 * what the API returned.
 */

function ToolChecklist({ tools, selectedTools, onToggle }) {
    if (tools.length === 0) {
        return (
            <div className="text-muted small">
                No verification tools are available for this sandbox's platform.
            </div>
        );
    }
    return (
        <div>
            {tools.map((tool) => (
                <div className="form-check" key={tool.id}>
                    <input
                        className="form-check-input"
                        type="checkbox"
                        id={`evasion-tool-${tool.id}`}
                        checked={selectedTools.includes(tool.id)}
                        onChange={() => onToggle(tool.id)}
                    />
                    <label
                        className="form-check-label"
                        htmlFor={`evasion-tool-${tool.id}`}
                    >
                        {tool.display_name}
                    </label>
                </div>
            ))}
        </div>
    );
}

function CustomOptionsPanel({
    availableTools,
    selectedTools,
    toolOptions,
    setToolOptions,
}) {
    if (selectedTools.length === 0) {
        return (
            <div className="text-muted small">
                Select at least one tool above to configure it.
            </div>
        );
    }
    return (
        <div className="card card-body bg-light mb-3">
            {selectedTools.map((toolId) => {
                const tool = availableTools.find((t) => t.id === toolId);
                if (!tool) return null;
                return (
                    <div className="mb-3" key={toolId}>
                        <div className="fw-bold mb-2">{tool.display_name}</div>
                        <EvasionToolOptions
                            tool={tool}
                            value={toolOptions[toolId]}
                            onChange={(value) =>
                                setToolOptions((current) => ({
                                    ...current,
                                    [toolId]: value,
                                }))
                            }
                        />
                    </div>
                );
            })}
        </div>
    );
}

function EvasionScanForm() {
    const [sandboxes, setSandboxes] = useState();
    const [error, setError] = useState();
    const [sandboxId, setSandboxId] = useState();
    const [selectedTools, setSelectedTools] = useState([]);
    const [profile, setProfile] = useState("full");
    const [toolOptions, setToolOptions] = useState({});
    const [submitting, setSubmitting] = useState(false);
    const [submitError, setSubmitError] = useState();
    const navigate = useNavigate();

    useEffect(() => {
        const abortController = new AbortController();
        getSandboxes({ abortController })
            .then((response) => {
                setSandboxes(response);
                if (response.length > 0) {
                    setSandboxId(response[0].id);
                    setSelectedTools(
                        response[0].available_tools.map((t) => t.id),
                    );
                }
            })
            .catch((err) => {
                if (!(err instanceof CanceledError)) {
                    setError(err);
                    console.error(err);
                }
            });
        return () => {
            abortController.abort();
        };
    }, []);

    if (typeof error !== "undefined") {
        return <div className="text-danger">Error: {error.toString()}</div>;
    }

    if (typeof sandboxes === "undefined") {
        return <div>Loading sandboxes...</div>;
    }

    if (sandboxes.length === 0) {
        return (
            <div className="text-muted">
                No sandboxes are configured for verification.
            </div>
        );
    }

    const currentSandbox = sandboxes.find((s) => s.id === sandboxId);
    const availableTools = currentSandbox ? currentSandbox.available_tools : [];

    const onSandboxChange = (id) => {
        setSandboxId(id);
        const sandbox = sandboxes.find((s) => s.id === id);
        setSelectedTools(
            sandbox ? sandbox.available_tools.map((t) => t.id) : [],
        );
        setToolOptions({});
    };

    const toggleTool = (toolId) => {
        setSelectedTools((current) =>
            current.includes(toolId)
                ? current.filter((t) => t !== toolId)
                : [...current, toolId],
        );
    };

    const submit = async (ev) => {
        ev.preventDefault();
        setSubmitting(true);
        setSubmitError(undefined);
        try {
            const relevantToolOptions = {};
            if (profile === "custom") {
                for (const toolId of selectedTools) {
                    if (toolOptions[toolId]) {
                        relevantToolOptions[toolId] = toolOptions[toolId];
                    }
                }
            }
            const result = await createScan({
                sandboxId,
                tools: selectedTools,
                profile,
                toolOptions: relevantToolOptions,
            });
            navigate(`/evasion/${result.scan_id}`);
        } catch (err) {
            setSubmitError(err);
            setSubmitting(false);
            console.error(err);
        }
    };

    return (
        <form onSubmit={submit}>
            <div className="mb-3">
                <label htmlFor="evasion-sandbox" className="form-label">
                    Sandbox
                </label>
                <select
                    className="form-select"
                    id="evasion-sandbox"
                    value={sandboxId}
                    onChange={(ev) => onSandboxChange(ev.target.value)}
                >
                    {sandboxes.map((sandbox) => (
                        <option key={sandbox.id} value={sandbox.id}>
                            {sandbox.display_name} ({sandbox.platform})
                        </option>
                    ))}
                </select>
            </div>

            <div className="mb-3">
                <label className="form-label">Verification tools</label>
                <ToolChecklist
                    tools={availableTools}
                    selectedTools={selectedTools}
                    onToggle={toggleTool}
                />
            </div>

            <div className="mb-3">
                <label className="form-label d-block">Scan profile</label>
                <div className="form-check form-check-inline">
                    <input
                        className="form-check-input"
                        type="radio"
                        name="profile"
                        id="evasion-profile-full"
                        checked={profile === "full"}
                        onChange={() => setProfile("full")}
                    />
                    <label
                        className="form-check-label"
                        htmlFor="evasion-profile-full"
                    >
                        Full
                    </label>
                </div>
                <div className="form-check form-check-inline">
                    <input
                        className="form-check-input"
                        type="radio"
                        name="profile"
                        id="evasion-profile-custom"
                        checked={profile === "custom"}
                        onChange={() => setProfile("custom")}
                    />
                    <label
                        className="form-check-label"
                        htmlFor="evasion-profile-custom"
                    >
                        Custom
                    </label>
                </div>
            </div>

            {profile === "custom" ? (
                <CustomOptionsPanel
                    availableTools={availableTools}
                    selectedTools={selectedTools}
                    toolOptions={toolOptions}
                    setToolOptions={setToolOptions}
                />
            ) : (
                []
            )}

            <div className="d-flex align-items-center">
                <button
                    className="btn btn-primary"
                    type="submit"
                    disabled={submitting || selectedTools.length === 0}
                >
                    Start scan
                </button>
                {submitError ? (
                    <div className="text-danger ms-3">
                        Error: {submitError.toString()}
                    </div>
                ) : (
                    []
                )}
            </div>
        </form>
    );
}

export default function SandboxEvasion() {
    return (
        <div className="container py-5" style={{ maxWidth: "800px" }}>
            <div className="card">
                <div className="card-body">
                    <div className="d-flex align-items-center mb-3">
                        <div>
                            <h4 className="mb-0">Sandbox Evasion</h4>
                            <small className="text-muted">
                                Verify how well this sandbox hides from
                                anti-analysis and sandbox-detection checks
                            </small>
                        </div>
                    </div>
                    <EvasionScanForm />
                </div>
            </div>
        </div>
    );
}
