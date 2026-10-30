import React from "react";
import { Link } from "react-router-dom";

/**
 * A small Markdown renderer for the bundled documentation (src/docs/content/*.md).
 *
 * It builds React elements and never injects HTML, so a page cannot carry markup or scripts. Supported:
 * front matter (`---` key: value `---`), headings #-####, paragraphs, - / 1. lists (nested by indent),
 * fenced code (```lang), ```diagram <name>``` blocks, tables, > quotes, --- rules, and the inline forms
 * `code`, **bold**, *italic* and [text](target). Targets: http(s)/mailto open in a new tab, `slug.md` or
 * `slug.md#anchor` go to another docs page, `#anchor` stays on the page, anything else renders as text.
 */

export function slugify(text) {
    return text
        .toLowerCase()
        .replace(/`/g, "")
        .replace(/[^a-z0-9\s-]/g, "")
        .trim()
        .replace(/\s+/g, "-");
}

export function parseFrontMatter(source) {
    const match = /^---\n([\s\S]*?)\n---\n?/.exec(source);
    if (!match) return { meta: {}, body: source };
    const meta = {};
    for (const line of match[1].split("\n")) {
        const kv = /^(\w+):\s*(.*)$/.exec(line.trim());
        if (kv) meta[kv[1]] = kv[2];
    }
    return { meta, body: source.slice(match[0].length) };
}

const FENCE = /^```\s*([\w-]*)\s*([\w-]*)\s*$/;
const HEADING = /^(#{1,4})\s+(.*)$/;
const LIST_ITEM = /^(\s*)([-*]|\d+\.)\s+(.*)$/;
const TABLE_RULE = /^\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)*\|?\s*$/;

const splitRow = (line) =>
    line
        .trim()
        .replace(/^\|/, "")
        .replace(/\|$/, "")
        .split("|")
        .map((cell) => cell.trim());

function startsBlock(line, next) {
    return (
        FENCE.test(line) ||
        HEADING.test(line) ||
        LIST_ITEM.test(line) ||
        line.startsWith(">") ||
        /^-{3,}\s*$/.test(line) ||
        (line.trim().startsWith("|") && TABLE_RULE.test(next || ""))
    );
}

// Lines of one list (and its indented continuation lines) -> nested item tree.
function parseList(lines) {
    const root = { children: [], ordered: false };
    const stack = [{ indent: -1, node: root }];
    for (const line of lines) {
        const item = LIST_ITEM.exec(line);
        if (item) {
            const indent = item[1].length;
            while (stack.length > 1 && indent <= stack[stack.length - 1].indent)
                stack.pop();
            const parent = stack[stack.length - 1].node;
            if (parent.children.length === 0)
                parent.ordered = /\d/.test(item[2]);
            const node = { text: item[3], children: [], ordered: false };
            parent.children.push(node);
            stack.push({ indent, node });
        } else if (stack.length > 1) {
            stack[stack.length - 1].node.text += " " + line.trim();
        }
    }
    return root;
}

export function parseBlocks(source) {
    const lines = source.replace(/\r\n/g, "\n").split("\n");
    const blocks = [];
    let i = 0;
    while (i < lines.length) {
        const line = lines[i];
        if (!line.trim()) {
            i += 1;
            continue;
        }
        const fence = FENCE.exec(line);
        if (fence) {
            const body = [];
            i += 1;
            while (i < lines.length && !/^```\s*$/.test(lines[i])) {
                body.push(lines[i]);
                i += 1;
            }
            i += 1; // closing fence (or end of file)
            if (fence[1] === "diagram")
                blocks.push({ type: "diagram", name: fence[2] });
            else
                blocks.push({
                    type: "code",
                    lang: fence[1],
                    text: body.join("\n"),
                });
            continue;
        }
        const heading = HEADING.exec(line);
        if (heading) {
            const text = heading[2].trim();
            blocks.push({
                type: "heading",
                level: heading[1].length,
                text,
                id: slugify(text),
            });
            i += 1;
            continue;
        }
        if (/^-{3,}\s*$/.test(line)) {
            blocks.push({ type: "rule" });
            i += 1;
            continue;
        }
        if (
            line.trim().startsWith("|") &&
            TABLE_RULE.test(lines[i + 1] || "")
        ) {
            const header = splitRow(line);
            const rows = [];
            i += 2;
            while (i < lines.length && lines[i].trim().startsWith("|")) {
                rows.push(splitRow(lines[i]));
                i += 1;
            }
            blocks.push({ type: "table", header, rows });
            continue;
        }
        if (line.startsWith(">")) {
            const body = [];
            while (i < lines.length && lines[i].startsWith(">")) {
                body.push(lines[i].replace(/^>\s?/, ""));
                i += 1;
            }
            blocks.push({
                type: "quote",
                blocks: parseBlocks(body.join("\n")),
            });
            continue;
        }
        if (LIST_ITEM.test(line)) {
            const body = [];
            while (
                i < lines.length &&
                lines[i].trim() &&
                (LIST_ITEM.test(lines[i]) || /^\s+\S/.test(lines[i]))
            ) {
                body.push(lines[i]);
                i += 1;
            }
            blocks.push({ type: "list", root: parseList(body) });
            continue;
        }
        const body = [line.trim()];
        i += 1;
        while (
            i < lines.length &&
            lines[i].trim() &&
            !startsBlock(lines[i], lines[i + 1])
        ) {
            body.push(lines[i].trim());
            i += 1;
        }
        blocks.push({ type: "paragraph", text: body.join(" ") });
    }
    return blocks;
}

const INLINE =
    /(`[^`]+`)|(\*\*[^*]+\*\*)|(\[[^\]]+\]\([^)\s]+\))|(\*[^*\s][^*]*\*)/;

function DocLink({ href, children }) {
    if (/^(https?:|mailto:)/.test(href))
        return (
            <a href={href} target="_blank" rel="noopener noreferrer">
                {children}
            </a>
        );
    if (/^#[\w-]+$/.test(href)) return <a href={href}>{children}</a>;
    const doc = /^([a-z0-9-]+)\.md(#[\w-]+)?$/.exec(href);
    if (doc)
        return <Link to={`/docs/${doc[1]}${doc[2] || ""}`}>{children}</Link>;
    return <span>{children}</span>;
}

export function renderInline(text, keyPrefix = "i") {
    const out = [];
    let rest = text;
    let n = 0;
    while (rest) {
        const match = INLINE.exec(rest);
        if (!match) {
            out.push(rest);
            break;
        }
        if (match.index > 0) out.push(rest.slice(0, match.index));
        const token = match[0];
        const key = `${keyPrefix}-${n++}`;
        if (match[1]) out.push(<code key={key}>{token.slice(1, -1)}</code>);
        else if (match[2])
            out.push(
                <strong key={key}>
                    {renderInline(token.slice(2, -2), key)}
                </strong>,
            );
        else if (match[3]) {
            const [, label, href] = /^\[([^\]]+)\]\(([^)\s]+)\)$/.exec(token);
            out.push(
                <DocLink key={key} href={href}>
                    {renderInline(label, key)}
                </DocLink>,
            );
        } else
            out.push(
                <em key={key}>{renderInline(token.slice(1, -1), key)}</em>,
            );
        rest = rest.slice(match.index + token.length);
    }
    return out;
}

function ListView({ node, k }) {
    const Tag = node.ordered ? "ol" : "ul";
    return (
        <Tag>
            {node.children.map((child, idx) => (
                <li key={idx}>
                    {renderInline(child.text, `${k}-${idx}`)}
                    {child.children.length ? (
                        <ListView node={child} k={`${k}-${idx}`} />
                    ) : null}
                </li>
            ))}
        </Tag>
    );
}

function Block({ block, k, diagrams }) {
    switch (block.type) {
        case "heading": {
            const Tag = `h${block.level}`;
            return (
                <Tag id={block.id} className="chimera-doc-heading">
                    {renderInline(block.text, k)}
                    {block.level > 1 ? (
                        <a
                            className="chimera-doc-anchor"
                            href={`#${block.id}`}
                            aria-label="Link to this section"
                        >
                            #
                        </a>
                    ) : null}
                </Tag>
            );
        }
        case "paragraph":
            return <p>{renderInline(block.text, k)}</p>;
        case "code":
            return (
                <div className="chimera-doc-code">
                    {block.lang ? (
                        <div className="chimera-doc-code__lang">
                            {block.lang}
                        </div>
                    ) : null}
                    <pre>
                        <code>{block.text}</code>
                    </pre>
                </div>
            );
        case "diagram": {
            const Diagram = diagrams?.[block.name];
            return Diagram ? (
                <Diagram />
            ) : (
                <p className="text-muted">
                    Diagram “{block.name}” is not available.
                </p>
            );
        }
        case "table":
            return (
                <div className="chimera-doc-table">
                    <table className="table table-sm">
                        <thead>
                            <tr>
                                {block.header.map((cell, idx) => (
                                    <th key={idx}>
                                        {renderInline(cell, `${k}-h${idx}`)}
                                    </th>
                                ))}
                            </tr>
                        </thead>
                        <tbody>
                            {block.rows.map((row, r) => (
                                <tr key={r}>
                                    {row.map((cell, c) => (
                                        <td key={c}>
                                            {renderInline(
                                                cell,
                                                `${k}-${r}-${c}`,
                                            )}
                                        </td>
                                    ))}
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            );
        case "quote":
            return (
                <blockquote className="chimera-doc-note">
                    {block.blocks.map((inner, idx) => (
                        <Block
                            key={idx}
                            block={inner}
                            k={`${k}-${idx}`}
                            diagrams={diagrams}
                        />
                    ))}
                </blockquote>
            );
        case "list":
            return <ListView node={block.root} k={k} />;
        case "rule":
            return <hr />;
        default:
            return null;
    }
}

export function Markdown({ blocks, diagrams }) {
    return (
        <>
            {blocks.map((block, idx) => (
                <Block
                    key={idx}
                    block={block}
                    k={`b${idx}`}
                    diagrams={diagrams}
                />
            ))}
        </>
    );
}
