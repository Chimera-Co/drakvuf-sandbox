import { beforeEach, expect, it, vi } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import DocsPage from "./DocsPage.jsx";
import { DIAGRAMS } from "./diagrams.jsx";
import { PAGES, buildPages } from "./pages.js";

const at = (path) =>
    render(
        <MemoryRouter initialEntries={[path]}>
            <Routes>
                <Route path="/docs" element={<DocsPage />} />
                <Route path="/docs/:slug" element={<DocsPage />} />
            </Routes>
        </MemoryRouter>,
    );

// jsdom has no scrolling; the page scrolls to the top or to the #anchor on navigation.
beforeEach(() => {
    window.scrollTo = vi.fn();
});

// Every block of every page, including those nested in quotes.
function* allBlocks(blocks) {
    for (const block of blocks) {
        yield block;
        if (block.type === "quote") yield* allBlocks(block.blocks);
    }
}

it("orders pages by file prefix and takes the slug and title from the file", () => {
    const pages = buildPages({
        "./content/02-second.md": "# Second page\n",
        "./content/01-first.md":
            "---\ntitle: First\ngroup: Start\n---\n# Ignored\n",
    });
    expect(pages.map((p) => [p.slug, p.title, p.group])).toEqual([
        ["first", "First", "Start"],
        ["second", "Second page", "Documentation"],
    ]);
});

it("bundles the documentation with a title, a group and a unique slug per page", () => {
    expect(PAGES.length).toBeGreaterThanOrEqual(10);
    const slugs = PAGES.map((p) => p.slug);
    expect(new Set(slugs).size).toBe(slugs.length);
    for (const page of PAGES) {
        expect(page.title, page.slug).toBeTruthy();
        expect(page.group, page.slug).not.toBe("Documentation");
        expect(page.blocks[0], page.slug).toMatchObject({
            type: "heading",
            level: 1,
        });
    }
});

it("links only to pages and diagrams that exist", () => {
    const slugs = new Set(PAGES.map((p) => p.slug));
    for (const page of PAGES) {
        for (const [, target] of page.text.matchAll(
            /\]\(([a-z0-9-]+)\.md[#)]/g,
        ))
            expect(slugs.has(target), `${page.slug} -> ${target}.md`).toBe(
                true,
            );
        for (const block of allBlocks(page.blocks))
            if (block.type === "diagram")
                expect(
                    DIAGRAMS[block.name],
                    `${page.slug}: ${block.name}`,
                ).toBeDefined();
    }
});

it("opens the first page at /docs with the page list and the outline", () => {
    at("/docs");
    expect(
        screen.getByRole("heading", {
            level: 1,
            name: "CHIMERA documentation",
        }),
    ).toBeInTheDocument();
    const nav = screen.getByRole("complementary", { name: "Documentation" });
    expect(within(nav).getByText("Concepts")).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: "Overview" })).toHaveClass(
        "active",
    );
    expect(
        within(nav).getByRole("link", { name: "VMI, Xen and DRAKVUF" }),
    ).toHaveAttribute("href", "/docs/concepts-vmi");
    expect(
        screen.getByRole("navigation", { name: "On this page" }),
    ).toBeInTheDocument();
});

it("renders a page by slug with its diagram and previous/next links", () => {
    at("/docs/architecture");
    expect(
        screen.getByRole("heading", { level: 1, name: "Architecture" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("img", { name: /CHIMERA components/ }),
    ).toBeInTheDocument();
    const pager = screen.getByRole("navigation", {
        name: "Previous and next page",
    });
    expect(
        within(pager).getByRole("link", { name: /How it was built/ }),
    ).toHaveAttribute("href", "/docs/how-it-was-built");
});

it("says so for an unknown page", () => {
    at("/docs/no-such-page");
    expect(
        screen.getByRole("heading", { name: "Page not found" }),
    ).toBeInTheDocument();
    expect(
        screen.getByRole("link", { name: "Go to the first page" }),
    ).toHaveAttribute("href", "/docs");
});

it("filters the page list by title and content", () => {
    at("/docs");
    const nav = screen.getByRole("complementary", { name: "Documentation" });
    fireEvent.change(within(nav).getByRole("searchbox"), {
        target: { value: "INetSim" },
    });
    expect(
        within(nav).getByRole("link", { name: /Network containment/ }),
    ).toBeInTheDocument();
    expect(
        within(nav).queryByRole("link", { name: "Classifier and fusion" }),
    ).toBeNull();
    fireEvent.change(within(nav).getByRole("searchbox"), {
        target: { value: "zzzz-not-there" },
    });
    expect(within(nav).getByText(/No page mentions/)).toBeInTheDocument();
});
