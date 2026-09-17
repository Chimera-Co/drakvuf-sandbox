import axios from "axios";

// api.js already sets this globally, but this module is deliberately kept
// standalone (not importing api.js) so evasion API calls never get
// accidentally coupled to analysis-only request/response shapes, mirroring
// how the backend keeps drakrun/web/evasion_api.py separate from api.py.
axios.defaults.baseURL = "/api";

export async function getSandboxes({ abortController } = {}) {
    const request = await axios.get(
        "/evasion/sandboxes",
        abortController ? { signal: abortController.signal } : {},
    );
    return request.data;
}

export async function getTools({ abortController } = {}) {
    const request = await axios.get(
        "/evasion/tools",
        abortController ? { signal: abortController.signal } : {},
    );
    return request.data;
}

export async function createScan({
    sandboxId,
    tools,
    profile,
    toolOptions = {},
}) {
    const request = await axios.post("/evasion/scans", {
        sandbox_id: sandboxId,
        tools,
        profile,
        tool_options: toolOptions,
    });
    return request.data;
}

export async function getScanList({ abortController } = {}) {
    const request = await axios.get(
        "/evasion/scans",
        abortController ? { signal: abortController.signal } : {},
    );
    return request.data;
}

export async function getScan({ scanId, abortController } = {}) {
    const request = await axios.get(
        `/evasion/scans/${scanId}`,
        abortController ? { signal: abortController.signal } : {},
    );
    return request.data;
}

export async function getScanStatus({ scanId, abortController } = {}) {
    const request = await axios.get(
        `/evasion/scans/${scanId}/status`,
        abortController ? { signal: abortController.signal } : {},
    );
    return request.data;
}

export async function getScanFileList({ scanId, abortController } = {}) {
    const request = await axios.get(
        `/evasion/scans/${scanId}/files`,
        abortController ? { signal: abortController.signal } : {},
    );
    return request.data;
}
