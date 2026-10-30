import { useEffect, useMemo, useState } from "react";
import { Link, NavLink, useLocation, useParams } from "react-router-dom";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
    faArrowLeft,
    faArrowRight,
    faBars,
    faMagnifyingGlass,
} from "@fortawesome/free-solid-svg-icons";
import { Markdown } from "./markdown.jsx";
import { DIAGRAMS } from "./diagrams.jsx";
import { PAGES, groupPages } from "./pages.js";
import "./docs.css";

function DocsNav({ pages, current, onPick }) {
    const [query, setQuery] = useState("");
    const q = query.trim().toLowerCase();
    const shown = q
        ? pages.filter(
              (p) => p.title.toLowerCase().includes(q) || p.text.includes(q),
          )
        : pages;
    return (
        <>
            <label className="chimera-docs__search">
                <FontAwesomeIcon icon={faMagnifyingGlass} aria-hidden="true" />
                <input
                    type="search"
                    className="form-control form-control-sm"
                    placeholder="Search the docs"
                    aria-label="Search the docs"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                />
            </label>
            {shown.length === 0 ? (
                <p className="chimera-docs__empty">
                    No page mentions “{query}”.
                </p>
            ) : null}
            {groupPages(shown).map((group) => (
                <div key={group.title} className="chimera-docs__group">
                    <div className="chimera-docs__group-title">
                        {group.title}
                    </div>
                    <ul>
                        {group.pages.map((page) => (
                            <li key={page.slug}>
                                <NavLink
                                    to={`/docs/${page.slug}`}
                                    className={
                                        page.slug === current
                                            ? "active"
                                            : undefined
                                    }
                                    onClick={onPick}
                                >
                                    {page.title}
                                </NavLink>
                            </li>
                        ))}
                    </ul>
                </div>
            ))}
        </>
    );
}

export default function DocsPage({ pages = PAGES }) {
    const { slug } = useParams();
    const { hash } = useLocation();
    const [navOpen, setNavOpen] = useState(false);
    const index = slug ? pages.findIndex((p) => p.slug === slug) : 0;
    const page = pages[index];
    const prev = index > 0 ? pages[index - 1] : null;
    const next =
        index >= 0 && index < pages.length - 1 ? pages[index + 1] : null;
    const article = useMemo(
        () =>
            page ? <Markdown blocks={page.blocks} diagrams={DIAGRAMS} /> : null,
        [page],
    );

    useEffect(() => {
        const target = hash ? document.getElementById(hash.slice(1)) : null;
        if (target) target.scrollIntoView?.();
        else window.scrollTo?.(0, 0);
    }, [slug, hash]);

    useEffect(() => {
        if (page) document.title = `${page.title} · CHIMERA docs`;
        return () => {
            document.title = "CHIMERA";
        };
    }, [page]);

    return (
        <div className="container-fluid px-4 chimera-docs">
            <div className="chimera-docs__layout">
                <aside className="chimera-docs__nav" aria-label="Documentation">
                    <button
                        type="button"
                        className="btn btn-sm btn-outline-secondary chimera-docs__nav-toggle"
                        aria-expanded={navOpen}
                        aria-controls="chimera-docs-pages"
                        onClick={() => setNavOpen(!navOpen)}
                    >
                        <FontAwesomeIcon icon={faBars} /> Contents
                    </button>
                    <div
                        id="chimera-docs-pages"
                        className={`chimera-docs__pages ${navOpen ? "is-open" : ""}`}
                    >
                        <DocsNav
                            pages={pages}
                            current={page?.slug}
                            onPick={() => setNavOpen(false)}
                        />
                    </div>
                </aside>

                <article className="chimera-docs__article">
                    {page ? (
                        <>
                            <div className="chimera-docs__crumb">
                                {page.group}
                            </div>
                            <div className="chimera-doc">{article}</div>
                            <nav
                                className="chimera-docs__pager"
                                aria-label="Previous and next page"
                            >
                                {prev ? (
                                    <Link to={`/docs/${prev.slug}`} rel="prev">
                                        <FontAwesomeIcon icon={faArrowLeft} />{" "}
                                        {prev.title}
                                    </Link>
                                ) : (
                                    <span />
                                )}
                                {next ? (
                                    <Link to={`/docs/${next.slug}`} rel="next">
                                        {next.title}{" "}
                                        <FontAwesomeIcon icon={faArrowRight} />
                                    </Link>
                                ) : null}
                            </nav>
                        </>
                    ) : (
                        <div className="chimera-doc">
                            <h1>Page not found</h1>
                            <p>
                                There is no documentation page called “{slug}”.{" "}
                                <Link to="/docs">Go to the first page</Link>.
                            </p>
                        </div>
                    )}
                </article>

                {page && page.toc.length > 1 ? (
                    <nav
                        className="chimera-docs__toc"
                        aria-label="On this page"
                    >
                        <div className="chimera-docs__group-title">
                            On this page
                        </div>
                        <ul>
                            {page.toc.map((h) => (
                                <li key={h.id}>
                                    <a href={`#${h.id}`}>
                                        {h.text.replace(/`/g, "")}
                                    </a>
                                </li>
                            ))}
                        </ul>
                    </nav>
                ) : null}
            </div>
        </div>
    );
}
