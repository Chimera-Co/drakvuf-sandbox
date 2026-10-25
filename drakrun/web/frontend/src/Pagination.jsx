import { useState } from "react";
import { useSearchParams } from "react-router-dom";

// 0 means "All". Rendering every row of a very large table would freeze the browser, so "All" is offered only up
// to ALL_LIMIT rows.
export const PAGE_SIZES = [10, 25, 50, 100, 0];
export const ALL_LIMIT = 5000;

function makePager(total, page, per, setPage, setPer) {
    const size = per === 0 ? Math.max(total, 1) : per;
    const pages = Math.max(1, Math.ceil(total / size));
    const current = Math.min(Math.max(page, 1), pages);
    return {
        page: current,
        per,
        pages,
        total,
        start: (current - 1) * size,
        end: Math.min(current * size, total),
        slice: (items) => items.slice((current - 1) * size, current * size),
        setPage,
        setPer,
    };
}

function allowed(per, total, defaultSize) {
    return per === 0 && total > ALL_LIMIT ? defaultSize : per;
}

// Page state in the URL (?page=2&per=25) so reload, back and shared links keep the place (list pages).
export function usePagination(total, defaultSize = 25) {
    const [params, setParams] = useSearchParams();
    const raw = params.get("per");
    const per =
        raw !== null && PAGE_SIZES.includes(Number(raw))
            ? Number(raw)
            : defaultSize;
    const requested = Number.parseInt(params.get("page"), 10);
    const update = (changes) => {
        const next = new URLSearchParams(params);
        for (const [key, value] of Object.entries(changes)) {
            if (value === null) next.delete(key);
            else next.set(key, String(value));
        }
        setParams(next, { replace: true });
    };
    return makePager(
        total,
        Number.isFinite(requested) ? requested : 1,
        allowed(per, total, defaultSize),
        (p) => update({ page: p === 1 ? null : p }),
        (size) =>
            update({ per: size === defaultSize ? null : size, page: null }),
    );
}

// Page state inside a component (tables within a report tab, several per page).
export function useLocalPagination(total, defaultSize = 25) {
    const [page, setPage] = useState(1);
    const [per, setPerState] = useState(defaultSize);
    return makePager(
        total,
        page,
        allowed(per, total, defaultSize),
        setPage,
        (size) => {
            setPerState(size);
            setPage(1);
        },
    );
}

// 1 … 4 5 [6] 7 8 … 20
function pageList(page, pages) {
    const wanted = new Set([
        1,
        pages,
        page - 2,
        page - 1,
        page,
        page + 1,
        page + 2,
    ]);
    const list = [...wanted]
        .filter((p) => p >= 1 && p <= pages)
        .sort((a, b) => a - b);
    const out = [];
    list.forEach((p, i) => {
        if (i && p - list[i - 1] > 1) out.push(`gap-${p}`);
        out.push(p);
    });
    return out;
}

export function Pagination({ pager, label, noun = "items" }) {
    const { page, pages, per, total, start, end, setPage, setPer } = pager;
    if (!total) return null;
    const item = (target, text, aria, disabled, current) => (
        <li
            key={aria}
            className={`page-item ${disabled ? "disabled" : ""} ${current ? "active" : ""}`}
        >
            <button
                type="button"
                className="page-link"
                aria-label={aria}
                aria-current={current ? "page" : undefined}
                disabled={disabled}
                onClick={() => setPage(target)}
            >
                {text}
            </button>
        </li>
    );
    return (
        <div className="chimera-pagination">
            <div className="small text-muted" aria-live="polite">
                <strong className="chimera-pagination-page">
                    Page {page} of {pages}
                </strong>
                <span className="mx-1">·</span>
                {start + 1}–{end} of {total} {noun}
            </div>
            {pages > 1 ? (
                <nav aria-label={label}>
                    <ul className="pagination pagination-sm">
                        {item(1, "«", "First page", page === 1)}
                        {item(page - 1, "‹", "Previous page", page === 1)}
                        {pageList(page, pages).map((p) =>
                            typeof p === "string" ? (
                                <li key={p} className="page-item disabled">
                                    <span className="page-link">…</span>
                                </li>
                            ) : (
                                item(p, p, `Page ${p}`, false, p === page)
                            ),
                        )}
                        {item(page + 1, "›", "Next page", page === pages)}
                        {item(pages, "»", "Last page", page === pages)}
                    </ul>
                </nav>
            ) : null}
            {pages > 7 ? (
                <label className="small d-flex align-items-center gap-2">
                    Go to
                    <input
                        type="number"
                        min={1}
                        max={pages}
                        className="form-control form-control-sm chimera-page-jump"
                        aria-label="Go to page"
                        defaultValue={page}
                        key={page}
                        onKeyDown={(e) => {
                            if (e.key !== "Enter") return;
                            const value = Number.parseInt(e.target.value, 10);
                            if (Number.isFinite(value))
                                setPage(Math.min(Math.max(value, 1), pages));
                        }}
                    />
                </label>
            ) : null}
            <label className="small d-flex align-items-center gap-2">
                Rows per page
                <select
                    className="form-select form-select-sm w-auto"
                    value={per}
                    onChange={(e) => setPer(Number(e.target.value))}
                >
                    {PAGE_SIZES.map((size) => (
                        <option
                            key={size}
                            value={size}
                            disabled={size === 0 && total > ALL_LIMIT}
                        >
                            {size === 0
                                ? total > ALL_LIMIT
                                    ? `All (over ${ALL_LIMIT})`
                                    : `All (${total})`
                                : size}
                        </option>
                    ))}
                </select>
            </label>
        </div>
    );
}
