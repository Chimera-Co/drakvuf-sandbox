/* global __APP_VERSION__ */
import React, { useEffect, useRef, useState } from "react";
import { Routes, Route, Link, NavLink, useLocation } from "react-router-dom";

import "./App.css";
import "startbootstrap-sb-admin/dist/css/styles.css";
// CHIMERA cosmetic theme. Imported last so it wins the cascade over Bootstrap
// and the sb-admin template at equal specificity.
import "./chimera-theme.css";
import "./themes.css";
import "./layout.css";
import { ThemePicker } from "./ThemePicker.jsx";
import AnalysisList from "./AnalysisList.jsx";
import UploadView from "./UploadView.jsx";
import AnalysisView from "./AnalysisView.jsx";
import SandboxEvasion from "./SandboxEvasion.jsx";
import EvasionScanView from "./EvasionScanView.jsx";
import VerificationRuns from "./VerificationRuns.jsx";
import { ChimeraLogo } from "./ChimeraLogo.jsx";
import { ChimeraIntro } from "./ChimeraIntro.jsx";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
    faAnglesLeft,
    faBars,
    faFolder,
    faUpload,
    faGear,
    faShieldHalved,
    faClockRotateLeft,
    faThumbtack,
} from "@fortawesome/free-solid-svg-icons";

const NAV_KEY = "chimera-sidebar";
// Analysis reports start with the sidebar folded to icons so the report gets the width; other pages start open.
const NAV_DEFAULTS = { report: "rail", other: "open" };
const PHONE = "(max-width: 767.98px)";

function loadNav() {
    try {
        return {
            ...NAV_DEFAULTS,
            ...JSON.parse(localStorage.getItem(NAV_KEY) || "{}"),
        };
    } catch {
        return { ...NAV_DEFAULTS };
    }
}

const isPhone = () =>
    typeof window !== "undefined" && !!window.matchMedia?.(PHONE).matches;

// Sidebar state: "open" or "rail" per kind of page (remembered in this browser), plus a transient peek that shows
// the folded sidebar over the page while the pointer or keyboard focus is on it.
export function useSidebar() {
    const { pathname } = useLocation();
    const kind = pathname.startsWith("/analysis/") ? "report" : "other";
    const [prefs, setPrefs] = useState(loadNav);
    const [peek, setPeek] = useState(false);
    useEffect(() => setPeek(false), [pathname]);
    const setMode = (mode) => {
        const next = { ...prefs, [kind]: mode };
        setPrefs(next);
        setPeek(false);
        try {
            localStorage.setItem(NAV_KEY, JSON.stringify(next));
        } catch {
            // private window or blocked storage: the choice lasts for this visit
        }
    };
    return { mode: prefs[kind], setMode, peek, setPeek };
}

export function AppHeader({ sidebar }) {
    const label = sidebar?.peek ? "Close menu" : "Open menu";
    return (
        <nav className="sb-topnav navbar navbar-expand navbar-dark bg-dark">
            {sidebar ? (
                <button
                    type="button"
                    id="sidebarToggle"
                    className="chimera-nav-toggle"
                    aria-label={label}
                    title={label}
                    aria-controls="layoutSidenav_nav"
                    aria-expanded={sidebar.peek}
                    onClick={() => sidebar.setPeek(!sidebar.peek)}
                >
                    <FontAwesomeIcon icon={faBars} />
                </button>
            ) : null}
            <Link
                className={`navbar-brand ps-3 ${sidebar ? "chimera-brand" : ""}`}
                to="/"
            >
                {/* Dark Solarized shell -> white ("light") creature variant. */}
                <ChimeraLogo
                    size={36}
                    variant="light"
                    className="chimera-brand-mark"
                />
                CHIMERA
            </Link>
            <ThemePicker />
        </nav>
    );
}

const NAV = [
    [
        "Analysis",
        [
            ["/", faFolder, "Analyses"],
            ["/upload", faUpload, "Upload sample"],
        ],
    ],
    [
        "Verification",
        [
            ["/verification-runs", faClockRotateLeft, "Verification Runs"],
            ["/evasion", faShieldHalved, "Sandbox Evasion"],
        ],
    ],
];

function AppSidenav({ sidebar }) {
    const timer = useRef();
    const { mode, setMode, peek, setPeek } = sidebar;
    const folded = mode === "rail" || isPhone();
    const later = (value, delay) => {
        clearTimeout(timer.current);
        timer.current = setTimeout(() => setPeek(value), delay);
    };
    useEffect(() => () => clearTimeout(timer.current), []);
    useEffect(() => {
        if (!peek) return undefined;
        const onKey = (e) => e.key === "Escape" && setPeek(false);
        const onDown = (e) => {
            if (!e.target.closest?.("#layoutSidenav_nav, #sidebarToggle"))
                setPeek(false);
        };
        document.addEventListener("keydown", onKey);
        document.addEventListener("pointerdown", onDown);
        return () => {
            document.removeEventListener("keydown", onKey);
            document.removeEventListener("pointerdown", onDown);
        };
    }, [peek, setPeek]);
    const peekProps = folded
        ? {
              onMouseEnter: () => !isPhone() && later(true, 120),
              onMouseLeave: () => later(false, 220),
              onFocus: () => {
                  clearTimeout(timer.current);
                  setPeek(true);
              },
              onBlur: (e) => {
                  if (!e.currentTarget.contains(e.relatedTarget))
                      later(false, 0);
              },
          }
        : {};
    const link = ([to, icon, text]) => (
        <NavLink
            key={to}
            className="nav-link"
            to={to}
            end={to === "/"}
            onClick={() => folded && setPeek(false)}
        >
            <div className="sb-nav-link-icon">
                <FontAwesomeIcon icon={icon} />
            </div>
            <span className="chimera-nav-label">{text}</span>
        </NavLink>
    );
    return (
        <div id="layoutSidenav_nav" {...peekProps}>
            <nav
                className="sb-sidenav accordion sb-sidenav-dark"
                id="sidenavAccordion"
                aria-label="Main"
            >
                <div className="sb-sidenav-menu">
                    {!isPhone() ? (
                        <div className="chimera-nav-tools">
                            {mode === "rail" ? (
                                <button
                                    type="button"
                                    onClick={() => setMode("open")}
                                    title="Keep the sidebar open on this kind of page"
                                >
                                    <FontAwesomeIcon icon={faThumbtack} />
                                    Pin open
                                </button>
                            ) : (
                                <button
                                    type="button"
                                    onClick={() => setMode("rail")}
                                    title="Fold the sidebar to icons; hover it to peek"
                                >
                                    <FontAwesomeIcon icon={faAnglesLeft} />
                                    Fold to icons
                                </button>
                            )}
                        </div>
                    ) : null}
                    <div className="nav">
                        {NAV.map(([heading, items]) => (
                            <React.Fragment key={heading}>
                                <div className="sb-sidenav-menu-heading">
                                    {heading}
                                </div>
                                {items.map(link)}
                            </React.Fragment>
                        ))}
                        <div className="sb-sidenav-menu-heading">Sandbox</div>
                        <a className="nav-link" href="/openapi/swagger">
                            <div className="sb-nav-link-icon">
                                <FontAwesomeIcon icon={faGear} />
                            </div>
                            <span className="chimera-nav-label">API docs</span>
                        </a>
                        <a className="nav-link" href="/rq">
                            <div className="sb-nav-link-icon">
                                <FontAwesomeIcon icon={faGear} />
                            </div>
                            <span className="chimera-nav-label">
                                RQ Dashboard
                            </span>
                        </a>
                    </div>
                </div>
                <div className="sb-sidenav-footer">
                    <div className="small">{__APP_VERSION__}</div>
                </div>
            </nav>
        </div>
    );
}

export function AppFooter() {
    return (
        <footer className="chimera-footer mt-auto">
            <div className="container-fluid px-4">
                <div className="chimera-footer__made">
                    Made with{" "}
                    <span className="chimera-footer__heart" aria-hidden="true">
                        &hearts;
                    </span>{" "}
                    in India by Team CHIMERA
                </div>
                <div className="chimera-footer__team">
                    Mantek Singh Burn &middot; Anusha Tiwari &middot; Shreyas
                    Tekawade
                </div>
                {/*
                  Upstream provenance / legal attribution intentionally NOT
                  rendered in the product UI. It is preserved in LICENSE and
                  COPYING at the repository root, which remain untouched.
                */}
            </div>
        </footer>
    );
}

export default function App() {
    const sidebar = useSidebar();
    return (
        <>
            <ChimeraIntro />
            <AppHeader sidebar={sidebar} />
            <div
                id="layoutSidenav"
                className={`chimera-shell ${sidebar.mode === "rail" ? "is-rail" : ""} ${sidebar.peek ? "is-peek" : ""}`}
            >
                <AppSidenav sidebar={sidebar} />
                <div id="layoutSidenav_content">
                    <main>
                        <Routes>
                            <Route path="/" element={<AnalysisList />} />
                            <Route path="/upload" element={<UploadView />} />
                            <Route
                                path="/analysis/:jobid"
                                element={<AnalysisView />}
                            />
                            <Route
                                path="/evasion"
                                element={<SandboxEvasion />}
                            />
                            <Route
                                path="/evasion/:scanId"
                                element={<EvasionScanView />}
                            />
                            <Route
                                path="/verification-runs"
                                element={<VerificationRuns />}
                            />
                        </Routes>
                    </main>
                    <AppFooter />
                </div>
            </div>
        </>
    );
}
