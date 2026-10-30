import { parseBlocks, parseFrontMatter } from "./markdown.jsx";

/**
 * The documentation pages: every src/docs/content/NN-slug.md, bundled at build time.
 * The NN prefix orders the pages, the rest of the file name is the URL slug (/docs/slug), and the front matter
 * gives the sidebar title and group. Adding a page means adding a file; nothing here needs to change.
 */

const FILES = import.meta.glob("./content/*.md", {
    query: "?raw",
    import: "default",
    eager: true,
});

export function buildPages(files) {
    return Object.entries(files)
        .map(([path, source]) => {
            const name = path.split("/").pop().replace(/\.md$/, "");
            const { meta, body } = parseFrontMatter(source);
            const blocks = parseBlocks(body);
            const h1 = blocks.find(
                (b) => b.type === "heading" && b.level === 1,
            );
            return {
                order: name,
                slug: name.replace(/^\d+-/, ""),
                title: meta.title || h1?.text || name,
                group: meta.group || "Documentation",
                summary: meta.summary || "",
                blocks,
                toc: blocks.filter(
                    (b) => b.type === "heading" && b.level === 2,
                ),
                text: body.toLowerCase(),
            };
        })
        .sort((a, b) => a.order.localeCompare(b.order));
}

export function groupPages(pages) {
    const groups = [];
    for (const page of pages) {
        let group = groups.find((g) => g.title === page.group);
        if (!group) {
            group = { title: page.group, pages: [] };
            groups.push(group);
        }
        group.pages.push(page);
    }
    return groups;
}

export const PAGES = buildPages(FILES);
