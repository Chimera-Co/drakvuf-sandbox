import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { Pagination, usePagination } from "./Pagination.jsx";

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
        expect(screen.getByText(/Showing 1–25 of 60 items/)).toBeTruthy();
        fireEvent.click(screen.getByRole("button", { name: "Next page" }));
        expect(screen.getByText(/Showing 26–50 of 60/)).toBeTruthy();
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
        expect(screen.getByText(/Showing 1–50 of 60/)).toBeTruthy();
    });
    it("clamps an out-of-range page and hides the pager for one page", () => {
        renderAt(30, "/?page=99");
        expect(screen.getByText(/Showing 26–30 of 30/)).toBeTruthy();
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
});
