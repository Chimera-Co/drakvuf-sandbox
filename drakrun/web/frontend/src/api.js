import axios from "axios";

axios.defaults.baseURL = "/api";

// Every analysis: live jobs plus the ones only on disk (the job registry keeps the newest 100)
export async function getAnalysisList({ abortController }) {
    const listRequest = await axios.get("/analyses", {
        signal: abortController.signal,
    });
    return listRequest.data;
}

export async function getAnalysisStatus({
    analysisId,
    abortController = undefined,
}) {
    const listRequest = await axios.get(
        `/status/${analysisId}`,
        abortController
            ? {
                  signal: abortController.signal,
              }
            : {},
    );
    return listRequest.data;
}

export async function getAnalysisSummary({
    analysisId,
    abortController = undefined,
}) {
    const reportRequest = await axios.get(
        `/report/${analysisId}`,
        abortController
            ? {
                  signal: abortController.signal,
              }
            : {},
    );
    return reportRequest.data;
}

export async function getAnalysisProcessTree({
    analysisId,
    abortController = undefined,
}) {
    const listRequest = await axios.get(
        `/processed/${analysisId}/process_tree`,
        abortController
            ? {
                  signal: abortController.signal,
              }
            : {},
    );
    return listRequest.data;
}

export async function getLog({ analysisId, logType, rangeStart, rangeEnd }) {
    const logRequest = await axios.get(`/logs/${analysisId}/${logType}`, {
        responseType: "text",
        headers: {
            Range: `bytes=${rangeStart}-${rangeEnd}`,
        },
    });
    return logRequest.data;
}

export async function getLogList({ analysisId }) {
    const logRequest = await axios.get(`/logs/${analysisId}`);
    return logRequest.data;
}

export async function getProcessInfo({ analysisId, processSeqId }) {
    const logRequest = await axios.get(
        `/process_info/${analysisId}/${processSeqId}`,
    );
    return logRequest.data;
}

export async function getProcessLog({
    analysisId,
    logType,
    selectedProcess,
    rangeStart,
    rangeEnd,
    methodsFilter = [],
}) {
    const logRequest = await axios.get(
        `/logs/${analysisId}/${logType}/process/${selectedProcess}`,
        {
            responseType: "text",
            headers: {
                Range: `bytes=${rangeStart}-${rangeEnd}`,
            },
            params: {
                filter: methodsFilter,
            },
        },
    );
    return logRequest.data;
}

export async function getAnalysisFileList({
    analysisId,
    abortController = undefined,
}) {
    const listRequest = await axios.get(
        `/files/${analysisId}`,
        abortController
            ? {
                  signal: abortController.signal,
              }
            : {},
    );
    return listRequest.data;
}

export async function uploadSample({
    file,
    guest_os = "windows",
    timeout,
    clock_scale,
    sleep_skip,
    file_name,
    file_path,
    plugins,
    start_command,
    start_method,
    start_working_dir,
    no_internet,
    no_screenshots,
    extract_archive,
    archive_password,
    archive_entry_path,
}) {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("guest_os", guest_os);
    formData.append("timeout", timeout);
    if (clock_scale) formData.append("clock_scale", clock_scale);
    if (sleep_skip) formData.append("sleep_skip", "1");
    formData.append("plugins", JSON.stringify(plugins));
    if (file_name) formData.append("file_name", file_name);
    if (file_path) formData.append("file_path", file_path);
    if (start_command) formData.append("start_command", start_command);
    if (start_method) formData.append("start_method", start_method);
    if (start_working_dir)
        formData.append("start_working_dir", start_working_dir);
    if (no_internet) formData.append("no_internet", "1");
    if (no_screenshots) formData.append("no_screenshots", "1");
    if (extract_archive) formData.append("extract_archive", "1");
    if (archive_password) formData.append("archive_password", archive_password);
    if (archive_entry_path)
        formData.append("archive_entry_path", archive_entry_path);
    const request = await axios.post("/upload", formData, {
        headers: {
            "Content-Type": "multipart/form-data",
        },
    });
    return request.data;
}

// Classifier verdict (chimera-verdict/1); 404 until postprocessing has classified the run
export async function getClassification({ analysisId }) {
    const request = await axios.get(`/classification/${analysisId}`);
    return request.data;
}

// Static analysis report (chimera-static/1); 404 until the static worker has finished
export async function getStaticReport({ analysisId }) {
    const request = await axios.get(`/static/${analysisId}`);
    return request.data;
}

// Deep static pass (chimera-deep/1: capa + FLOSS); 404 until it has run, or when it does not apply
export async function getDeepStatic({ analysisId }) {
    const request = await axios.get(`/static/${analysisId}/deep`);
    return request.data;
}

// One JADX-decompiled file of an APK, as text; only the paths mobsf.json lists
export async function getMobsfSource({ analysisId, path, signal }) {
    const request = await axios.get(`/static/${analysisId}/mobsf/source`, {
        params: { path },
        responseType: "text",
        transformResponse: (data) => data,
        signal,
    });
    return request.data;
}

// MobSF APK scan (chimera-mobsf/1); 404 until it has run, or for anything but an APK
export async function getMobsf({ analysisId }) {
    const request = await axios.get(`/static/${analysisId}/mobsf`);
    return request.data;
}

// Memory-dump scan (chimera-memdumps/1); 404 until the deep worker has scanned the run's dumps
export async function getMemdumps({ analysisId }) {
    const request = await axios.get(`/static/${analysisId}/memdumps`);
    return request.data;
}

// Analyst report (chimera-report/1: assessment, claims, ATT&CK, IOCs); 404 until postprocessing has written it
export async function getChimeraReport({ analysisId }) {
    const request = await axios.get(`/chimera_report/${analysisId}`);
    return request.data;
}

// Where each stage of the analysis is (upload, static, VM run, classifier, deep, memory dumps, intel, report)
export async function getPipeline({ analysisId }) {
    const request = await axios.get(`/pipeline/${analysisId}`);
    return request.data;
}
