import { useSearchParams } from "react-router-dom";

export const PAGE_SIZES = [10, 25, 50, 100];

// Page state lives in the URL (?page=2&per=25) so reload, back and shared links keep the place.
export function usePagination(total, defaultSize = 25) {
    const [params, setParams] = useSearchParams();
    const per = PAGE_SIZES.includes(Number(params.get("per")))
        ? Number(params.get("per"))
        : defaultSize;
    const pages = Math.max(1, Math.ceil(total / per));
    const requested = Number.parseInt(params.get("page"), 10);
    const page = Number.isFinite(requested)
        ? Math.min(Math.max(requested, 1), pages)
        : 1;
    const update = (changes) => {
        const next = new URLSearchParams(params);
        for (const [key, value] of Object.entries(changes)) {
            if (value === null) next.delete(key);
            else next.set(key, String(value));
        }
        setParams(next, { replace: true });
    };
    return {
        page,
        per,
        pages,
        total,
        start: (page - 1) * per,
        slice: (items) => items.slice((page - 1) * per, page * per),
        setPage: (p) => update({ page: p === 1 ? null : p }),
        setPer: (size) =>
            update({ per: size === defaultSize ? null : size, page: null }),
    };
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
    const { page, pages, per, total, start, setPage, setPer } = pager;
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
                Showing {start + 1}–{Math.min(start + per, total)} of {total}{" "}
                {noun}
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
            <label className="small d-flex align-items-center gap-2">
                Per page
                <select
                    className="form-select form-select-sm w-auto"
                    value={per}
                    onChange={(e) => setPer(Number(e.target.value))}
                >
                    {PAGE_SIZES.map((size) => (
                        <option key={size} value={size}>
                            {size}
                        </option>
                    ))}
                </select>
            </label>
        </div>
    );
}
