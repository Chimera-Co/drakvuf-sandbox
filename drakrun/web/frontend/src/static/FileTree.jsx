import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
    faFolder,
    faFolderOpen,
    faFile,
    faFileCode,
    faFileLines,
    faTerminal,
} from "@fortawesome/free-solid-svg-icons";
import { useEffect, useMemo, useRef, useState } from "react";

export function buildFileTree(files) {
    const roots = [];
    for (const file of files) {
        const parts = file.path.split("/").filter(Boolean);
        let children = roots;
        let path = "";
        parts.forEach((name, index) => {
            path = path ? `${path}/${name}` : name;
            if (index === parts.length - 1) {
                children.push({ ...file, id: file.id || path, name });
            } else {
                let folder = children.find((n) => n.id === path && n.children);
                if (!folder) {
                    folder = { id: path, name, children: [] };
                    children.push(folder);
                }
                children = folder.children;
            }
        });
    }
    return roots;
}

export function compactFolders(nodes) {
    return nodes.map((node) => {
        let current = { ...node };
        while (
            current.compact !== false &&
            current.children?.length === 1 &&
            current.children[0].children &&
            !current.badges
        ) {
            const child = current.children[0];
            current = {
                ...child,
                name: `${current.name}/${child.name}`,
                ids: [...(current.ids || [current.id]), child.id],
            };
        }
        return current.children
            ? { ...current, children: compactFolders(current.children) }
            : current;
    });
}

export function filterTree(nodes, query) {
    if (!query) return nodes;
    const needle = query.toLowerCase();
    return nodes.flatMap((node) => {
        if (node.children) {
            const children = filterTree(node.children, query);
            return children.length ? [{ ...node, children }] : [];
        }
        return `${node.path || node.name} ${node.search || ""} ${node.meta || ""}`
            .toLowerCase()
            .includes(needle)
            ? [node]
            : [];
    });
}

export function FileTree({
    nodes,
    selected,
    onOpen,
    defaultExpanded = [],
    reveal,
    label = "Explorer",
    query: controlledQuery,
    onQueryChange,
    filterLabel = "Filter files",
}) {
    const [localQuery, setQuery] = useState("");
    const query = controlledQuery ?? localQuery;
    const [expanded, setExpanded] = useState(() => {
        const initial = new Set(defaultExpanded);
        const visit = (items) =>
            items.forEach((n) => {
                if (n.ids?.some((id) => initial.has(id))) initial.add(n.id);
                if (n.children) visit(n.children);
            });
        visit(compactFolders(nodes));
        return initial;
    });
    const [collapsed, setCollapsed] = useState(new Set());
    useEffect(() => {
        if (reveal) {
            setCollapsed(new Set());
            setLimit(400);
        }
    }, [reveal]);
    const revealPath = typeof reveal === "string" ? reveal : reveal?.path;
    const [focused, setFocused] = useState(null);
    const [limit, setLimit] = useState(400);
    const refs = useRef(new Map());
    const tree = useMemo(
        () => filterTree(compactFolders(nodes), query),
        [nodes, query],
    );
    const rows = [];
    const visit = (items, level = 1, parent = null) =>
        items.forEach((node) => {
            const opened =
                !!query ||
                (!collapsed.has(node.id) &&
                    (expanded.has(node.id) ||
                        (revealPath &&
                            (revealPath === node.id ||
                                revealPath.startsWith(`${node.id}/`) ||
                                node.ids?.includes(revealPath)))));
            rows.push({ node, level, parent, opened });
            if (node.children && opened)
                visit(node.children, level + 1, node.id);
        });
    visit(tree);
    const revealIndex = revealPath
        ? rows.findIndex(
              ({ node }) =>
                  node.id === revealPath || node.ids?.includes(revealPath),
          )
        : -1;
    const visible = rows.slice(0, Math.max(limit, revealIndex + 1));
    const revealId = rows[revealIndex]?.node.id;
    useEffect(() => {
        if (revealId)
            refs.current.get(revealId)?.scrollIntoView?.({ block: "nearest" });
    }, [reveal, revealId, collapsed]);
    const active = visible.some(({ node }) => node.id === focused)
        ? focused
        : visible[0]?.node.id;
    const toggle = (id, open) => {
        setCollapsed((old) => {
            const next = new Set(old);
            if (open) next.delete(id);
            else next.add(id);
            return next;
        });
        setExpanded((old) => {
            const next = new Set(old);
            if (open) next.add(id);
            else next.delete(id);
            return next;
        });
    };
    const focus = (id) => {
        setFocused(id);
        refs.current.get(id)?.focus();
    };
    const highlight = (name) => {
        const index = query
            ? name.toLowerCase().indexOf(query.toLowerCase())
            : -1;
        return index < 0 ? (
            name
        ) : (
            <>
                {name.slice(0, index)}
                <mark>{name.slice(index, index + query.length)}</mark>
                {name.slice(index + query.length)}
            </>
        );
    };
    const render = (items) =>
        items.map(({ node, level, parent, opened }) => {
            const folder = !!node.children;
            const extension =
                node.extension || (node.path || node.name).split(".").pop();
            const icon = folder
                ? opened
                    ? "folder-open"
                    : "folder"
                : {
                      java: "file-code-o",
                      kt: "file-code-o",
                      c: "file-code-o",
                      asm: "file-text-o",
                      py: "file-code-o",
                      js: "file-code-o",
                      sh: "terminal",
                      ps1: "terminal",
                      python: "file-code-o",
                      javascript: "file-code-o",
                      powershell: "terminal",
                      bash: "terminal",
                  }[extension] || "file-o";
            return (
                <div
                    key={node.id}
                    role="treeitem"
                    aria-label={node.name}
                    title={[node.path || node.name, node.meta]
                        .filter(Boolean)
                        .join(" · ")}
                    aria-level={level}
                    aria-expanded={folder ? opened : undefined}
                    aria-selected={
                        !folder && (node.value || node.id) === selected
                    }
                    tabIndex={active === node.id ? 0 : -1}
                    ref={(el) => {
                        if (el) refs.current.set(node.id, el);
                        else refs.current.delete(node.id);
                    }}
                    onFocus={(event) => {
                        event.stopPropagation();
                        setFocused(node.id);
                    }}
                    onClick={(event) => {
                        event.stopPropagation();
                        folder ? toggle(node.id, !opened) : onOpen(node);
                    }}
                    onKeyDown={(event) => {
                        event.stopPropagation();
                        const index = visible.findIndex(
                            (row) => row.node.id === node.id,
                        );
                        let target;
                        switch (event.key) {
                            case "ArrowDown":
                                target =
                                    visible[
                                        Math.min(index + 1, visible.length - 1)
                                    ]?.node.id;
                                break;
                            case "ArrowUp":
                                target =
                                    visible[Math.max(0, index - 1)]?.node.id;
                                break;
                            case "Home":
                                target = visible[0]?.node.id;
                                break;
                            case "End":
                                target = visible.at(-1)?.node.id;
                                break;
                            case "ArrowRight":
                                if (folder && !opened) toggle(node.id, true);
                                else if (folder)
                                    target = visible[index + 1]?.node.id;
                                break;
                            case "ArrowLeft":
                                if (folder && opened) toggle(node.id, false);
                                else target = parent;
                                break;
                            case "Enter":
                            case " ":
                                if (folder) toggle(node.id, !opened);
                                else onOpen(node);
                                break;
                            default:
                                return;
                        }
                        event.preventDefault();
                        if (target) focus(target);
                    }}
                >
                    <div
                        className="file-tree-row"
                        style={{
                            paddingLeft: `${(level - 1) * 16 + 6}px`,
                            "--tree-level": level,
                        }}
                    >
                        <span className="file-tree-chevron" aria-hidden="true">
                            {folder ? (opened ? "⌄" : "›") : ""}
                        </span>
                        <FontAwesomeIcon
                            aria-hidden="true"
                            icon={
                                {
                                    folder: faFolder,
                                    "folder-open": faFolderOpen,
                                    "file-code-o": faFileCode,
                                    "file-text-o": faFileLines,
                                    terminal: faTerminal,
                                    "file-o": faFile,
                                }[icon]
                            }
                            className={`file-icon ext-${extension}`}
                        />
                        <span className="file-tree-name">
                            {highlight(node.name)}
                        </span>
                        {node.badges}
                        <small className="file-tree-meta">{node.meta}</small>
                    </div>
                    {folder && opened && (
                        <div role="group">{nested(node.id)}</div>
                    )}
                </div>
            );
        });
    // Nested groups preserve the accessible hierarchy while only expanded rows are mounted.
    const nested = (parent = null) =>
        visible
            .filter((row) => row.parent === parent)
            .flatMap((row) => render([row]));
    return (
        <div className="file-explorer">
            <div className="file-tree-head">
                <div className="d-flex justify-content-between">
                    <strong>{label}</strong>
                    <button
                        type="button"
                        className="btn btn-sm btn-link"
                        onClick={() => {
                            setExpanded(new Set());
                            setCollapsed(new Set(rows.map((r) => r.node.id)));
                        }}
                    >
                        Collapse all
                    </button>
                </div>
                <label className="small w-100">
                    {filterLabel}
                    <input
                        className="form-control form-control-sm"
                        value={query}
                        onChange={(e) => {
                            (onQueryChange || setQuery)(e.target.value);
                            setLimit(400);
                        }}
                    />
                </label>
            </div>
            <div role="tree" aria-label={label}>
                {nested()}
            </div>
            {!rows.length && <p className="small p-2">No files match.</p>}
            {rows.length > visible.length && (
                <button
                    className="btn btn-sm btn-link"
                    onClick={() => setLimit(visible.length + 400)}
                >
                    Show more ({rows.length - visible.length})
                </button>
            )}
        </div>
    );
}

export function buildFunctionTree(functions, name = "Program") {
    const entry = [],
        capa = new Map(),
        namespaces = [],
        other = [];
    const leaf = (f, prefix) => ({
        id: `${prefix}/${f.address}`,
        value: f.address,
        name: f.name,
        meta: `${f.address} · ${f.size ?? "?"} B`,
        search: `${f.name} ${(f.capa || []).join(" ")}`,
        extension: "c",
        function: f,
    });
    for (const f of functions) {
        const isEntry = (f.reasons || []).some(
            (r) => r === "entry" || r === "export",
        );
        if (isEntry) entry.push(leaf(f, "entry"));
        for (const rule of f.capa || []) {
            if (!capa.has(rule)) capa.set(rule, []);
            capa.get(rule).push(leaf(f, `capa/${rule}`));
        }
        if (f.name.includes("::"))
            namespaces.push({
                ...leaf(f, "namespace"),
                path: f.name.replaceAll("::", "/"),
            });
        else if (!isEntry && !f.capa?.length) other.push(leaf(f, "other"));
    }
    const namespaceNodes = (items) =>
        items.map((node) =>
            node.children
                ? {
                      ...node,
                      id: `namespace-folder/${node.id}`,
                      children: namespaceNodes(node.children),
                  }
                : node,
        );
    return [
        {
            id: "program",
            name: `Program (${name})`,
            children: [
                {
                    id: "entry",
                    name: "Entry points & exports",
                    children: entry,
                },
                {
                    id: "capa",
                    compact: false,
                    name: "capa matches",
                    children: [...capa].map(([rule, children]) => ({
                        id: `capa/${rule}`,
                        name: rule,
                        children,
                    })),
                },
                {
                    id: "namespaces",
                    compact: false,
                    name: "Namespaces",
                    children: namespaceNodes(buildFileTree(namespaces)),
                },
                { id: "other", name: "Other functions", children: other },
            ],
        },
    ];
}
