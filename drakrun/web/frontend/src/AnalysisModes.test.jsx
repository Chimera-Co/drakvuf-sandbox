import { afterEach, expect, it, vi } from "vitest";
import {
    cleanup,
    fireEvent,
    render,
    screen,
    waitFor,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import UploadView from "./UploadView.jsx";
import { AnalysisReport } from "./AnalysisReport.jsx";
import { uploadSample } from "./api.js";

vi.mock("./AnalysisFiles.jsx", () => ({ AnalysisFilesViewer: () => null }));
vi.mock("./api.js", () => ({ uploadSample: vi.fn() }));
vi.mock("./intelApi.js", () => ({
    getIntel: vi.fn().mockResolvedValue({ data: { status: "unavailable" } }),
    refreshIntel: vi.fn().mockResolvedValue({ data: { status: "queued" } }),
    getIntelProviders: vi
        .fn()
        .mockRejectedValue(new Error("settings unavailable")),
}));
vi.mock("./PluginPicker.jsx", () => ({
    PluginPicker: () => <input name="plugins" value="procmon" readOnly />,
}));
vi.mock("./AnalysisReportContext.jsx", () => ({
    useAnalysisReport: () => ({
        analysisInfo: {
            id: "test",
            options: { mode: "static-only", plugins: [] },
            chimera_report: true,
            html_report: true,
        },
        getAnalysisSummary: vi.fn(),
        isOffline: false,
    }),
}));
vi.mock("./AnalysisVerdict.jsx", () => ({
    VerdictCard: () => <div>Verdict card</div>,
    StaticAnalysisTab: () => <div>Static results</div>,
}));
vi.mock("./AnalysisMetadataTable.jsx", () => ({
    AnalysisMetadataTable: () => <div>Metadata</div>,
}));
afterEach(() => {
    cleanup();
    vi.clearAllMocks();
});

it("defaults to combined and sends only static inputs in static-only mode", async () => {
    uploadSample.mockResolvedValue({ task_uid: "test" });
    render(
        <MemoryRouter>
            <UploadView />
        </MemoryRouter>,
    );
    expect(screen.getByLabelText("Mode").value).toBe("combined");
    expect(screen.getByLabelText("Platform")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("Mode"), {
        target: { value: "static-only" },
    });
    expect(document.querySelector('[name="timeout"]')).toBeNull();
    expect(document.querySelector('[name="plugins"]')).toBeNull();
    expect(document.querySelector('[name="start_command"]')).toBeNull();
    expect(document.querySelector('[name="extract_archive"]')).toBeNull();
    expect(document.querySelector('[name="no_internet"]')).toBeNull();
    const file = new File(["fixture"], "x.bin");
    fireEvent.change(document.querySelector('[name="file"]'), {
        target: { files: [file] },
    });
    fireEvent.submit(document.querySelector("form"));
    await waitFor(() => expect(uploadSample).toHaveBeenCalledOnce());
    expect(Object.keys(uploadSample.mock.calls[0][0]).sort()).toEqual([
        "file",
        "mode",
    ]);
});

it("shows static results and printable report without a dynamic run", () => {
    render(<AnalysisReport />);
    expect(screen.getByText("Verdict card")).toBeTruthy();
    expect(screen.getByText("Static results")).toBeTruthy();
    expect(screen.getByText("Printable report")).toBeTruthy();
    for (const text of [
        "Process info",
        "General logs",
        "Screenshots",
        "HTML report",
        "Summary report",
    ]) {
        expect(screen.queryByText(text)).toBeNull();
    }
});
