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
import { getIntelProviders } from "./intelApi.js";
import { uploadSample } from "./api.js";

vi.mock("./intelApi.js", () => ({ getIntelProviders: vi.fn() }));
vi.mock("./api.js", () => ({ uploadSample: vi.fn() }));
vi.mock("./PluginPicker.jsx", () => ({
    PluginPicker: () => <input name="plugins" value="procmon" readOnly />,
}));
afterEach(() => {
    cleanup();
    vi.clearAllMocks();
});

it("defaults online checkbox from server and stores opt-out for static uploads", async () => {
    getIntelProviders.mockResolvedValue({
        data: { online_enabled: true, online_default: true },
    });
    uploadSample.mockResolvedValue({ task_uid: "fixture" });
    render(
        <MemoryRouter>
            <UploadView />
        </MemoryRouter>,
    );
    const checkbox = await screen.findByLabelText(
        /Online threat-intel lookups/,
    );
    await waitFor(() => expect(checkbox.checked).toBe(true));
    fireEvent.click(checkbox);
    fireEvent.change(screen.getByLabelText("Mode"), {
        target: { value: "static-only" },
    });
    const file = document.querySelector('input[type="file"]');
    fireEvent.change(file, {
        target: { files: [new File(["fixture"], "fixture.bin")] },
    });
    fireEvent.submit(document.querySelector("form"));
    await waitFor(() => expect(uploadSample).toHaveBeenCalledOnce());
    expect(uploadSample.mock.calls[0][0].intel_online).toBe(false);
});

it("disables online checkbox with configuration explanation", async () => {
    getIntelProviders.mockResolvedValue({
        data: { online_enabled: false, online_default: true },
    });
    render(
        <MemoryRouter>
            <UploadView />
        </MemoryRouter>,
    );
    await screen.findByText(/Online lookups are disabled/);
    const checkbox = screen.getByLabelText(/Online threat-intel lookups/);
    expect(checkbox.disabled).toBe(true);
    expect(checkbox.checked).toBe(false);
});

it("sends an Android APK as a static-only analysis", async () => {
    getIntelProviders.mockResolvedValue({
        data: { online_enabled: false, online_default: false },
    });
    uploadSample.mockResolvedValue({ task_uid: "fixture" });
    render(
        <MemoryRouter>
            <UploadView />
        </MemoryRouter>,
    );
    fireEvent.change(screen.getByLabelText("Platform"), {
        target: { value: "android" },
    });
    expect(screen.getByText(/The app is not run/)).toBeTruthy();
    expect(screen.getByLabelText("Mode").disabled).toBe(true);
    expect(screen.queryByText(/Analysis time/)).toBeNull();
    const file = document.querySelector('input[type="file"]');
    expect(file.accept).toContain(".apk");
    fireEvent.change(file, {
        target: { files: [new File(["PK"], "app.apk")] },
    });
    fireEvent.submit(document.querySelector("form"));
    await waitFor(() => expect(uploadSample).toHaveBeenCalledOnce());
    expect(uploadSample.mock.calls[0][0].mode).toBe("static-only");
});

it("refuses a non-APK file for Android", async () => {
    getIntelProviders.mockResolvedValue({ data: { online_enabled: false } });
    render(
        <MemoryRouter>
            <UploadView />
        </MemoryRouter>,
    );
    fireEvent.change(screen.getByLabelText("Platform"), {
        target: { value: "android" },
    });
    fireEvent.change(document.querySelector('input[type="file"]'), {
        target: { files: [new File(["MZ"], "tool.exe")] },
    });
    expect(await screen.findByText(/takes an APK file/)).toBeTruthy();
    expect(screen.getByText("Analyze").disabled).toBe(true);
});
