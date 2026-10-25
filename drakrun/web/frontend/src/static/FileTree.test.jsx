import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import {
    FileTree,
    buildFileTree,
    compactFolders,
    filterTree,
    buildFunctionTree,
} from "./FileTree.jsx";
import ghidra from "../__fixtures__/deep-ghidra.json";
afterEach(cleanup);
const files = [
    { path: "org/fdroid/fdroid/Main.java" },
    { path: "org/fdroid/fdroid/Other.kt" },
    { path: "lib/Call.java" },
];
it("compacts folder chains and keeps ancestors of matching files", () => {
    const tree = compactFolders(buildFileTree(files));
    expect(tree[0].name).toBe("org/fdroid/fdroid");
    const filtered = filterTree(tree, "Main");
    expect(filtered).toHaveLength(1);
    expect(filtered[0].children.map((n) => n.name)).toEqual(["Main.java"]);
});
it("navigates, expands, opens and collapses with the keyboard", () => {
    const open = vi.fn();
    render(<FileTree nodes={buildFileTree(files)} onOpen={open} />);
    const root = screen.getByRole("treeitem", { name: "org/fdroid/fdroid" });
    root.focus();
    fireEvent.keyDown(root, { key: "ArrowRight" });
    fireEvent.keyDown(root, { key: "ArrowRight" });
    const main = screen.getByRole("treeitem", { name: "Main.java" });
    expect(main).toHaveFocus();
    fireEvent.keyDown(main, { key: "Enter" });
    expect(open).toHaveBeenCalledWith(
        expect.objectContaining({ path: files[0].path }),
    );
    fireEvent.keyDown(main, { key: "ArrowDown" });
    expect(screen.getByRole("treeitem", { name: "Other.kt" })).toHaveFocus();
    fireEvent.keyDown(document.activeElement, { key: "ArrowLeft" });
    expect(root).toHaveFocus();
    fireEvent.keyDown(root, { key: "ArrowLeft" });
    expect(root).toHaveAttribute("aria-expanded", "false");
    fireEvent.keyDown(root, { key: "End" });
    expect(screen.getByRole("treeitem", { name: "lib" })).toHaveFocus();
    fireEvent.keyDown(document.activeElement, { key: "Home" });
    expect(root).toHaveFocus();
});
it("filters collapsed folders, highlights matches and caps large expanded trees", () => {
    render(<FileTree nodes={buildFileTree(files)} onOpen={() => {}} />);
    fireEvent.change(screen.getByLabelText("Filter files"), {
        target: { value: "Main" },
    });
    expect(screen.getByRole("treeitem", { name: "Main.java" })).toBeVisible();
    expect(screen.getByText("Main", { selector: "mark" })).toBeVisible();
    cleanup();
    render(
        <FileTree
            nodes={buildFileTree(
                Array.from({ length: 3001 }, (_, i) => ({
                    path: `file${i}.c`,
                })),
            )}
            onOpen={() => {}}
        />,
    );
    expect(screen.getAllByRole("treeitem")).toHaveLength(400);
    fireEvent.click(screen.getByText(/Show more/));
    expect(screen.getAllByRole("treeitem")).toHaveLength(800);
});
it("groups entry, capa and namespaced functions in the logical tree", () => {
    const functions = [
        ...ghidra.ghidra.functions,
        { name: "net::client::connect", address: "0x42", size: 10 },
    ];
    const nodes = buildFunctionTree(functions, "sample.exe");
    render(
        <FileTree
            nodes={nodes}
            defaultExpanded={["program", "entry", "capa", "namespaces"]}
            onOpen={() => {}}
        />,
    );
    expect(screen.getByRole("treeitem", { name: "entry" })).toHaveTextContent(
        "0x140001000",
    );
    fireEvent.click(
        screen.getByRole("treeitem", { name: "create process on Windows" }),
    );
    expect(screen.getAllByRole("treeitem", { name: "entry" })).toHaveLength(2);
    fireEvent.click(screen.getByRole("treeitem", { name: "net/client" }));
    expect(screen.getByRole("treeitem", { name: "connect" })).toHaveTextContent(
        "0x42",
    );
});
