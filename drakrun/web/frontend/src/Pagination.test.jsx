import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import {
    ALL_LIMIT,
    Pagination,
    useLocalPagination,
    usePagination,
} from "./Pagination.jsx";

afterEach(cleanup);

function List({ total }) {
    const items = Array.from({ length: total }, (_, i) => `item-${i + 1}`);
    const pager = usePagination(total);
    const location = useLocation();
    return (
        <>
            <ul aria-label="items">
                {pager.slice(items).map((i) => (
                    <li key={i}>{i}</li>
                ))}
            </ul>
            <Pagination pager={pager} label="Pages" noun="items" />
            <output aria-label="query">{location.search}</output>
        </>
    );
}

const renderAt = (total, url = "/") =>
    render(
        <MemoryRouter initialEntries={[url]}>
            <List total={total} />
        </MemoryRouter>,
    );

describe("pagination", () => {
    it("shows the first page and moves with the buttons", () => {
        renderAt(60);
        expect(
            screen
                .getAllByRole("listitem")
                .filter((li) => li.textContent.startsWith("item")),
        ).toHaveLength(25);
        expect(screen.getByText(/1–25 of 60 items/)).toBeTruthy();
        expect(screen.getByText("Page 1 of 3")).toBeTruthy();
        fireEvent.click(screen.getByRole("button", { name: "Next page" }));
        expect(screen.getByText(/26–50 of 60/)).toBeTruthy();
        expect(screen.getByLabelText("query").textContent).toBe("?page=2");
        fireEvent.click(screen.getByRole("button", { name: "Last page" }));
        expect(screen.getByText("item-60")).toBeTruthy();
        expect(screen.getByRole("button", { name: "Next page" }).disabled).toBe(
            true,
        );
    });
    it("changing the page size goes back to page 1", () => {
        renderAt(60, "/?page=3");
        fireEvent.change(screen.getByRole("combobox"), {
            target: { value: "50" },
        });
        expect(screen.getByLabelText("query").textContent).toBe("?per=50");
        expect(screen.getByText(/1–50 of 60/)).toBeTruthy();
    });
    it("clamps an out-of-range page and hides the pager for one page", () => {
        renderAt(30, "/?page=99");
        expect(screen.getByText(/26–30 of 30/)).toBeTruthy();
        cleanup();
        renderAt(5);
        expect(screen.queryByRole("navigation")).toBeNull();
    });
    it("collapses long page lists", () => {
        renderAt(1000, "/?page=20");
        const labels = screen.getAllByRole("button").map((b) => b.textContent);
        expect(labels).toEqual([
            "«",
            "‹",
            "1",
            "18",
            "19",
            "20",
            "21",
            "22",
            "40",
            "›",
            "»",
        ]);
        expect(screen.getAllByText("…")).toHaveLength(2);
    });
    it("shows every row with All and remembers it in the URL", () => {
        renderAt(60);
        fireEvent.change(screen.getByRole("combobox"), {
            target: { value: "0" },
        });
        expect(screen.getByLabelText("query").textContent).toBe("?per=0");
        expect(screen.getByText("Page 1 of 1")).toBeTruthy();
        expect(screen.getByText("item-60")).toBeTruthy();
        expect(screen.getByRole("option", { name: "All (60)" })).toBeTruthy();
    });
    it("does not offer All for huge totals", () => {
        renderAt(ALL_LIMIT + 1, "/?per=0");
        expect(screen.getByText(/1–25 of/)).toBeTruthy();
        expect(
            screen.getByRole("option", { name: /^All \(over/ }).disabled,
        ).toBe(true);
    });
    it("jumps to a typed page on long lists", () => {
        renderAt(1000);
        const jump = screen.getByRole("spinbutton", { name: "Go to page" });
        fireEvent.change(jump, { target: { value: "33" } });
        fireEvent.keyDown(jump, { key: "Enter" });
        expect(screen.getByText("Page 33 of 40")).toBeTruthy();
    });
});

function LocalTable({ total }) {
    const items = Array.from({ length: total }, (_, i) => `row-${i + 1}`);
    const pager = useLocalPagination(total, 10);
    return (
        <>
            <ul aria-label="rows">
                {pager.slice(items).map((i) => (
                    <li key={i}>{i}</li>
                ))}
            </ul>
            <Pagination pager={pager} label="Rows" noun="rows" />
        </>
    );
}

describe("local pagination", () => {
    it("pages without touching the URL", () => {
        render(<LocalTable total={35} />);
        expect(screen.getByText("Page 1 of 4")).toBeTruthy();
        fireEvent.click(screen.getByRole("button", { name: "Page 4" }));
        expect(screen.getByText(/31–35 of 35 rows/)).toBeTruthy();
        fireEvent.change(screen.getByRole("combobox"), {
            target: { value: "25" },
        });
        expect(screen.getByText("Page 1 of 2")).toBeTruthy();
    });
});
