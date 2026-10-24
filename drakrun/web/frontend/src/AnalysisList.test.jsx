import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import AnalysisList from "./AnalysisList.jsx";
import { getAnalysisList } from "./api";
vi.mock("./api");
afterEach(cleanup);
const rows = [
    {
        id: "one",
        status: "finished",
        file: {
            name: "Example.exe",
            md5: "abcd1234",
            sha1: "dead5678",
            sha256: "beef9012",
        },
        options: { guest_os: "windows" },
        classification: { label: "unknown" },
    },
    {
        id: "two",
        status: "queued",
        file: { name: "Other.elf" },
        options: { guest_os: "linux" },
    },
    {
        id: "three",
        status: "finished",
        file: { name: "Clean.exe" },
        classification: { label: "benign" },
    },
];
function Location() {
    return <div data-testid="location">{useLocation().search}</div>;
}
async function setup(query = "") {
    getAnalysisList.mockResolvedValue(rows);
    render(
        <MemoryRouter initialEntries={["/" + query]}>
            <AnalysisList />
            <Location />
        </MemoryRouter>,
    );
    await screen.findByLabelText("Search name or hash");
}
describe("analysis filters", () => {
    it.each(["abcd", "dead", "beef", "EXAMPLE", "abcd1234"])(
        "searches names and hashes: %s",
        async (q) => {
            await setup();
            fireEvent.change(screen.getByLabelText("Search name or hash"), {
                target: { value: q },
            });
            expect(screen.getByRole("link", { name: "one" })).toBeTruthy();
            expect(screen.queryByRole("link", { name: "two" })).toBeNull();
            expect(screen.getByTestId("location").textContent).toContain(
                "q=" + q,
            );
        },
    );
    it("restores no verdict and distinguishes not classified", async () => {
        await setup("?verdict=no+verdict");
        expect(screen.getByRole("link", { name: "one" })).toBeTruthy();
        expect(screen.queryByRole("link", { name: "two" })).toBeNull();
        fireEvent.change(screen.getByLabelText("Verdict"), {
            target: { value: "not classified" },
        });
        expect(screen.getByRole("link", { name: "two" })).toBeTruthy();
        expect(screen.queryByRole("link", { name: "one" })).toBeNull();
    });
    it("combines filters", async () => {
        await setup("?os=windows&status=finished&verdict=benign");
        expect(screen.getByRole("link", { name: "three" })).toBeTruthy();
        fireEvent.change(screen.getByLabelText("OS"), {
            target: { value: "linux" },
        });
        expect(
            screen.getByText("No analyses match these filters."),
        ).toBeTruthy();
    });
});
