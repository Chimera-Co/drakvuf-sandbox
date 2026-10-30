import { expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import {
    Markdown,
    parseBlocks,
    parseFrontMatter,
    renderInline,
    slugify,
} from "./markdown.jsx";

const show = (source, diagrams) =>
    render(
        <MemoryRouter>
            <Markdown blocks={parseBlocks(source)} diagrams={diagrams} />
        </MemoryRouter>,
    );

it("reads front matter and leaves the body", () => {
    const { meta, body } = parseFrontMatter(
        "---\ntitle: Static analysis\ngroup: Concepts\n---\n# Static\n",
    );
    expect(meta).toEqual({ title: "Static analysis", group: "Concepts" });
    expect(body).toBe("# Static\n");
    expect(parseFrontMatter("# No front matter").meta).toEqual({});
});

it("parses headings, code, diagrams, tables, quotes and nested lists", () => {
    const blocks = parseBlocks(
        [
            "# Title",
            "## Build `drakvuf` now",
            "Some text",
            "on two lines.",
            "```bash",
            "make -j4",
            "```",
            "```diagram pipeline",
            "```",
            "| A | B |",
            "|---|---|",
            "| 1 | 2 |",
            "> a note",
            "- one",
            "  - nested",
            "- two",
            "",
            "1. first",
        ].join("\n"),
    );
    expect(blocks.map((b) => b.type)).toEqual([
        "heading",
        "heading",
        "paragraph",
        "code",
        "diagram",
        "table",
        "quote",
        "list",
        "list",
    ]);
    expect(blocks[1]).toMatchObject({ level: 2, id: "build-drakvuf-now" });
    expect(blocks[2].text).toBe("Some text on two lines.");
    expect(blocks[3]).toMatchObject({ lang: "bash", text: "make -j4" });
    expect(blocks[4].name).toBe("pipeline");
    expect(blocks[5]).toMatchObject({ header: ["A", "B"], rows: [["1", "2"]] });
    expect(blocks[7].root.children[0].children[0].text).toBe("nested");
    expect(blocks[8].root.ordered).toBe(true);
});

it("renders links by kind and never turns unknown targets into links", () => {
    render(
        <MemoryRouter>
            <p>
                {renderInline(
                    "[ext](https://example.org) [page](build-drakvuf.md#patches) [here](#top) [bad](javascript:alert(1))",
                )}
            </p>
        </MemoryRouter>,
    );
    const ext = screen.getByRole("link", { name: "ext" });
    expect(ext).toHaveAttribute("href", "https://example.org");
    expect(ext).toHaveAttribute("target", "_blank");
    expect(ext).toHaveAttribute("rel", "noopener noreferrer");
    expect(screen.getByRole("link", { name: "page" })).toHaveAttribute(
        "href",
        "/docs/build-drakvuf#patches",
    );
    expect(screen.getByRole("link", { name: "here" })).toHaveAttribute(
        "href",
        "#top",
    );
    expect(screen.queryByRole("link", { name: "bad" })).toBeNull();
});

it("renders markup in the source as text", () => {
    const { container } = show(
        "Run <script>alert(1)</script> **now** and `<b>`",
    );
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    expect(container.querySelector("strong").textContent).toBe("now");
    expect(container.textContent).toContain("<script>alert(1)</script>");
});

it("renders a known diagram and names an unknown one", () => {
    const Pipeline = () => <div data-testid="pipeline" />;
    show("```diagram pipeline\n```\n```diagram nope\n```", {
        pipeline: Pipeline,
    });
    expect(screen.getByTestId("pipeline")).toBeInTheDocument();
    expect(
        screen.getByText(/Diagram “nope” is not available/),
    ).toBeInTheDocument();
});

it("makes stable heading ids", () => {
    expect(slugify("1. Host and Xen")).toBe("1-host-and-xen");
    expect(slugify("What `capa` finds")).toBe("what-capa-finds");
});
