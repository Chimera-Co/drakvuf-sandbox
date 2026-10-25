import { afterEach, expect, it, vi } from "vitest";
import {
    cleanup,
    fireEvent,
    render,
    screen,
    waitFor,
} from "@testing-library/react";
import { StructuredTable } from "./StructuredLogs.jsx";
import { FileExplorer, buildFileTree } from "./AnalysisExplorer.jsx";
import { ScreenshotFilmstrip } from "./AnalysisScreenshotViewer.jsx";
import { ProcessTreeView } from "./ProcessTreeView.jsx";
import { VerdictCard } from "./AnalysisVerdict.jsx";
import {
    CodeExplorer,
    GenericBlock,
    SourceViewer,
} from "./static/CodeExplorer.jsx";
import { tokenizers } from "./static/highlight.js";
import { getClassification } from "./api.js";
import verdict from "./__fixtures__/classification.json";
import processTree from "./__fixtures__/process-tree.json";
const { getTree } = vi.hoisted(() => ({ getTree: vi.fn() }));
vi.mock("./AnalysisReportContext.jsx", () => ({
    useAnalysisReport: () => ({ getAnalysisProcessTree: getTree }),
}));
vi.mock("./api.js", () => ({ getClassification: vi.fn() }));
vi.mock("axios", () => ({
    default: { get: vi.fn(), defaults: { baseURL: "/api" } },
}));
vi.mock("recharts", () => ({
    ResponsiveContainer: ({ children }) => <div>{children}</div>,
    BarChart: () => null,
    Bar: () => null,
    XAxis: () => null,
    YAxis: () => null,
    Tooltip: () => null,
    LineChart: () => null,
    Line: () => null,
    Legend: () => null,
}));
afterEach(() => {
    cleanup();
    vi.clearAllMocks();
});
const fixtures = import.meta.glob("./__fixtures__/logs/*.log", {
    query: "?raw",
    import: "default",
    eager: true,
});
it.each([
    "apimon",
    "regmon",
    "filetracer",
    "procmon",
    "socketmon",
    "tlsmon",
    "exmon",
    "memdump",
    "cpuidmon",
    "inject",
])("renders structured %s fixture events", (plugin) => {
    const row = JSON.parse(
        fixtures[`./__fixtures__/logs/${plugin}.log`].split("\n")[0],
    );
    render(<StructuredTable rows={[row]} logType={plugin} />);
    expect(
        screen.getByRole("region", { name: `${plugin} events` }),
    ).toBeTruthy();
    expect(screen.getByRole("columnheader", { name: "Process" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Inspect" }));
    expect(
        screen.getByRole("dialog", { name: "Event details" }).textContent,
    ).toContain(row.Plugin);
});
it("shows hostile event content as text and pages events", () => {
    const { container } = render(
        <StructuredTable
            logType="regmon"
            rows={Array.from({ length: 70 }, (_, PID) => ({
                PID,
                Value: '<img src=x onerror="alert(1)">',
            }))}
        />,
    );
    expect(screen.getAllByRole("button", { name: "Inspect" })).toHaveLength(50);
    fireEvent.click(screen.getAllByRole("button", { name: "Inspect" })[0]);
    expect(screen.getByRole("dialog").textContent).toContain(
        "<img src=x onerror",
    );
    expect(container.querySelector("img")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Close details" }));
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(screen.getAllByRole("button", { name: "Inspect" })).toHaveLength(20);
});
it("builds virtual folders and nested directories", () => {
    const files = [
        "apimon.log",
        "dump.pcap",
        "dumps.zip",
        "report.json",
        "static.json",
        "nested/a.txt",
    ];
    const tree = buildFileTree(files);
    expect(tree.logs["apimon.log"].file).toBe("apimon.log");
    expect(tree.files.nested["a.txt"].file).toBe("nested/a.txt");
    render(<FileExplorer files={files} analysisId="test" />);
    expect(screen.getByLabelText("Analysis folders").textContent).toContain(
        "network",
    );
    fireEvent.click(screen.getByRole("button", { name: "dumps.zip" }));
    expect(
        screen
            .getByRole("link", { name: "Download file" })
            .getAttribute("href"),
    ).toContain("filename=dumps.zip");
});
it("moves through screenshots with thumbnails and keyboard", () => {
    render(
        <ScreenshotFilmstrip
            images={[
                { index: 1, timestamp: 100 },
                { index: 2, timestamp: 102 },
            ]}
            getURL={(i) => `/image/${i}`}
        />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Open screenshot 2" }));
    expect(
        screen.getByRole("img", { name: "screenshot-2" }).getAttribute("src"),
    ).toBe("/image/2");
    fireEvent.keyDown(
        screen.getByRole("region", { name: "Screenshot viewer" }),
        { key: "ArrowLeft" },
    );
    expect(screen.getByRole("img", { name: "screenshot-1" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Play" }));
    expect(screen.getByRole("button", { name: "Pause" })).toBeTruthy();
});
it("marks descendants, searches by PID and selects a process", async () => {
    getTree.mockResolvedValue([
        {
            seqid: 1,
            pid: 10,
            procname: "system",
            children: [
                {
                    seqid: 2,
                    pid: 20,
                    procname: "sample.exe",
                    args: [],
                    children: [
                        {
                            seqid: 3,
                            pid: 30,
                            procname: "child.exe",
                            children: [],
                        },
                    ],
                },
            ],
        },
    ]);
    const onSelect = vi.fn();
    render(
        <ProcessTreeView
            analysisId="test"
            sampleName="sample.exe"
            onProcessSelect={onSelect}
        />,
    );
    await screen.findByText("sample");
    fireEvent.change(screen.getByLabelText("Search process name or PID"), {
        target: { value: "30" },
    });
    expect(screen.getByText("descendant")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /child.exe/ }));
    expect(onSelect).toHaveBeenCalledWith(3);
});
it("renders the benign process-tree fixture", async () => {
    getTree.mockResolvedValue(processTree);
    render(
        <ProcessTreeView
            analysisId="fixture"
            sampleName="test.exe"
            onProcessSelect={() => {}}
        />,
    );
    await waitFor(() =>
        expect(screen.queryByText("Loading process tree...")).toBeNull(),
    );
    expect(screen.getByText("Process tree")).toBeTruthy();
});
it("shows score meters, disagreement and calibration note", async () => {
    getClassification.mockResolvedValue(verdict);
    render(<VerdictCard analysisId="test" />);
    expect(
        (
            await screen.findByRole("meter", { name: "Decision score (0-1)" })
        ).getAttribute("aria-valuenow"),
    ).toBe(String(verdict.score));
    expect(screen.getAllByRole("meter")).toHaveLength(3);
    expect(
        screen.getByText(
            "Scores are not probabilities until the model is calibrated; 0.50 is the malicious threshold.",
        ),
    ).toBeTruthy();
    expect(screen.getByText("Dynamic and static disagree")).toBeTruthy();
});
it("renders future calibrated probability", async () => {
    getClassification.mockResolvedValue({
        ...verdict,
        calibrated_probability: 0.72,
    });
    render(<VerdictCard analysisId="test" />);
    expect(
        await screen.findByText("Calibrated probability: 72.0%"),
    ).toBeTruthy();
});
it.each(Object.keys(tokenizers))(
    "tokenizes %s without losing hostile text",
    (language) => {
        const source =
            'if ($x) { return "<script>alert(1)</script>"; }\n# comment';
        const tokens = tokenizers[language](source);
        expect(tokens.map((t) => t.text).join("")).toBe(source);
        expect(tokens.some((t) => t.kind !== "plain")).toBe(true);
    },
);
it("recognizes C types, calls, labels and preprocessor", () => {
    const tokens = tokenizers.c(
        "#include <x>\nundefined8 fn(uint x) { label: return call(0xff); }",
    );
    for (const kind of [
        "preprocessor",
        "type",
        "function",
        "label",
        "number",
        "keyword",
    ])
        expect(tokens.some((t) => t.kind === kind)).toBe(true);
});
it("navigates call graph and disassembly", () => {
    const functions = [
        {
            address: "0x1",
            name: "entry",
            reasons: ["entry"],
            c: "return 1;",
            calls: ["0x2"],
        },
        {
            address: "0x2",
            name: "worker",
            c: "return 2;",
            callers: ["0x1"],
            asm: [{ a: "0x2", b: "c3", t: "RET" }],
        },
    ];
    render(<CodeExplorer format="pe" deep={{ ghidra: { functions } }} />);
    fireEvent.click(screen.getByRole("button", { name: "Navigate to worker" }));
    fireEvent.click(screen.getByLabelText("Disassembly"));
    expect(screen.getByText("RET")).toBeTruthy();
});
it("renders unknown blocks and decoded source layers as text", () => {
    const { container } = render(
        <>
            <GenericBlock
                value={{ custom: { value: "<script>test</script>" } }}
            />
            <SourceViewer
                source={{
                    language: "powershell",
                    text: 'Write-Host "<script>"',
                    layers: [
                        {
                            method: "base64",
                            language: "javascript",
                            text: "return 42;",
                        },
                    ],
                }}
            />
        </>,
    );
    expect(container.querySelector("script")).toBeNull();
    expect(container.textContent).toContain("<script>test</script>");
    fireEvent.click(screen.getByRole("button", { name: "base64" }));
    expect(screen.getByLabelText("Script source text").textContent).toContain(
        "return 42;",
    );
});

it("treats prototype-like file names as ordinary path segments", () => {
    const tree = buildFileTree(["__proto__/a.txt", "constructor/b.txt"]);
    expect(tree.files.__proto__["a.txt"].file).toBe("__proto__/a.txt");
    expect(tree.files.constructor["b.txt"].file).toBe("constructor/b.txt");
    expect(Object.prototype["a.txt"]).toBeUndefined();
});

it("loads process byte ranges and preserves an event split across chunks", async () => {
    const { default: axios } = await import("axios");
    const { StructuredLogViewer } = await import("./StructuredLogs.jsx");
    const text = JSON.stringify({
        PID: 2,
        Method: "Write",
        Value: "x".repeat(270000),
    });
    const bytes = new TextEncoder().encode(text);
    let requests = 0;
    axios.get.mockImplementation((path, options) => {
        if (path.endsWith("/stats"))
            return Promise.resolve({ data: { methods: [] } });
        expect(path).toContain("/regmon/process/7");
        const offset = requests++ * 262144;
        expect(options.headers.Range).toBe(
            `bytes=${offset}-${offset + 262143}`,
        );
        return Promise.resolve({
            status: 200,
            data: bytes.slice(offset, offset + 262144).buffer,
            headers: {},
        });
    });
    render(
        <StructuredLogViewer
            analysisId="test"
            logType="regmon"
            selectedProcess={7}
        />,
    );
    await waitFor(() =>
        expect(
            screen.getByRole("button", { name: "Load next chunk" }).disabled,
        ).toBe(false),
    );
    fireEvent.click(screen.getByRole("button", { name: "Load next chunk" }));
    expect(await screen.findByRole("button", { name: "Inspect" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "End of log" }).disabled).toBe(
        true,
    );
    expect(requests).toBe(2);
});

it("finishes raw logs without a trailing newline", async () => {
    const { _logLoader } = await import("./LogViewer.jsx");
    const getLogEntries = vi.fn().mockResolvedValue("last line");
    const loader = _logLoader({ getLogEntries, chunkSize: 100 });
    expect(await loader.next()).toEqual({ done: false, value: "last line" });
    expect((await loader.next()).done).toBe(true);
    expect(getLogEntries).toHaveBeenCalledTimes(1);
});
