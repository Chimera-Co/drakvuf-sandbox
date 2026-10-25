import { useEffect, useId, useRef, useState } from "react";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faListUl, faXmark } from "@fortawesome/free-solid-svg-icons";

// A tab fixed on the screen edge that opens a panel over the page. Hovering the tab peeks (the panel closes again
// when the pointer leaves it); a click opens it until it is closed with the button, Escape or a click outside.
export function EdgeDrawer({
    side = "left",
    label,
    icon,
    title = label,
    hidden = false,
    children,
}) {
    const [state, setState] = useState("closed"); // closed | peek | open
    const timer = useRef();
    const box = useRef(null);
    const tab = useRef(null);
    const panelId = useId();
    const later = (next, delay) => {
        clearTimeout(timer.current);
        timer.current = setTimeout(() => setState(next), delay);
    };
    useEffect(() => () => clearTimeout(timer.current), []);
    useEffect(() => {
        if (hidden) setState("closed");
    }, [hidden]);
    useEffect(() => {
        // a peek the pointer never moves into closes by itself
        if (state === "peek") later("closed", 1500);
    }, [state]);
    useEffect(() => {
        if (state === "closed") return undefined;
        const onKey = (e) => {
            if (e.key !== "Escape") return;
            setState("closed");
            tab.current?.focus();
        };
        const onDown = (e) => {
            if (
                !box.current?.contains(e.target) &&
                !tab.current?.contains(e.target)
            )
                setState("closed");
        };
        document.addEventListener("keydown", onKey);
        document.addEventListener("pointerdown", onDown);
        return () => {
            document.removeEventListener("keydown", onKey);
            document.removeEventListener("pointerdown", onDown);
        };
    }, [state]);
    if (hidden) return null;
    const open = state !== "closed";
    return (
        <>
            {!open ? (
                <button
                    ref={tab}
                    type="button"
                    className={`chimera-edge-tab is-${side}`}
                    aria-expanded={false}
                    aria-controls={panelId}
                    onClick={() => setState("open")}
                    onMouseEnter={() => later("peek", 160)}
                    onMouseLeave={() => clearTimeout(timer.current)}
                >
                    {icon ? <FontAwesomeIcon icon={icon} /> : null}
                    {label}
                </button>
            ) : null}
            {open ? (
                <aside
                    ref={box}
                    id={panelId}
                    className={`chimera-edge-drawer is-${side}`}
                    aria-label={title}
                    onMouseEnter={() => clearTimeout(timer.current)}
                    onMouseLeave={() =>
                        state === "peek" && later("closed", 350)
                    }
                    onPointerDown={() => state === "peek" && setState("open")}
                    onFocus={() => state === "peek" && setState("open")}
                >
                    <header>
                        <h2>{title}</h2>
                        <button
                            type="button"
                            className="btn btn-sm btn-outline-secondary"
                            aria-label={`Close ${title}`}
                            onClick={() => setState("closed")}
                        >
                            <FontAwesomeIcon icon={faXmark} />
                        </button>
                    </header>
                    <div className="chimera-edge-body">
                        {typeof children === "function"
                            ? children({ close: () => setState("closed") })
                            : children}
                    </div>
                </aside>
            ) : null}
        </>
    );
}

// True while `ref`'s element is out of view (scrolled past), e.g. the process-tree peek tab appears once the tree
// card at the top of the report has scrolled away.
export function useOutOfView(ref) {
    const [out, setOut] = useState(false);
    useEffect(() => {
        const el = ref.current;
        if (!el || typeof IntersectionObserver === "undefined")
            return undefined;
        const observer = new IntersectionObserver(
            ([entry]) => setOut(!entry.isIntersecting),
            { rootMargin: "-56px 0px 0px 0px" },
        );
        observer.observe(el);
        return () => observer.disconnect();
    }, [ref]);
    return out;
}

const reducedMotion = () =>
    typeof window !== "undefined" &&
    !!window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

// Right-edge outline of the sections on a long page: items are [{id, label, count}] of elements on the page with
// that id. The section under the top bar is highlighted while the page scrolls.
export function SectionOutline({ items, title = "Outline" }) {
    const [current, setCurrent] = useState(items[0]?.id);
    useEffect(() => {
        let frame;
        const onScroll = () => {
            cancelAnimationFrame(frame);
            frame = requestAnimationFrame(() => {
                let active = items[0]?.id;
                for (const item of items) {
                    const el = document.getElementById(item.id);
                    if (el && el.getBoundingClientRect().top <= 96)
                        active = item.id;
                }
                setCurrent(active);
            });
        };
        onScroll();
        window.addEventListener("scroll", onScroll, { passive: true });
        return () => {
            window.removeEventListener("scroll", onScroll);
            cancelAnimationFrame(frame);
        };
    }, [items]);
    if (items.length < 2) return null;
    return (
        <EdgeDrawer side="right" label="Outline" icon={faListUl} title={title}>
            <nav aria-label={title}>
                <ol className="chimera-outline">
                    {items.map((item) => (
                        <li
                            key={item.id}
                            className={item.count === 0 ? "is-empty" : ""}
                        >
                            <a
                                href={`#${item.id}`}
                                className={
                                    current === item.id ? "is-current" : ""
                                }
                                aria-current={
                                    current === item.id ? "location" : undefined
                                }
                                onClick={(e) => {
                                    e.preventDefault();
                                    const el = document.getElementById(item.id);
                                    el?.scrollIntoView({
                                        behavior: reducedMotion()
                                            ? "auto"
                                            : "smooth",
                                        block: "start",
                                    });
                                    setCurrent(item.id);
                                }}
                            >
                                {item.label}
                                {item.count != null ? (
                                    <span className="badge bg-secondary">
                                        {item.count}
                                    </span>
                                ) : null}
                            </a>
                        </li>
                    ))}
                </ol>
            </nav>
        </EdgeDrawer>
    );
}
