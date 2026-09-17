import React from "react";
import { Routes, Route, Link } from "react-router-dom";

import "./App.css";
import "startbootstrap-sb-admin/dist/css/styles.css";
// CHIMERA cosmetic theme. Imported last so it wins the cascade over Bootstrap
// and the sb-admin template at equal specificity.
import "./chimera-theme.css";
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
    faFolder,
    faUpload,
    faGear,
    faShieldHalved,
    faClockRotateLeft,
} from "@fortawesome/free-solid-svg-icons";

export function AppHeader() {
    return (
        <nav className="sb-topnav navbar navbar-expand navbar-dark bg-dark">
            <Link className="navbar-brand ps-3" to="/">
                {/* Dark Solarized shell -> white ("light") creature variant. */}
                <ChimeraLogo
                    size={36}
                    variant="light"
                    className="chimera-brand-mark"
                />
                CHIMERA
            </Link>
        </nav>
    );
}

function AppSidenav() {
    return (
        <div id="layoutSidenav_nav">
            <nav
                className="sb-sidenav accordion sb-sidenav-dark"
                id="sidenavAccordion"
            >
                <div className="sb-sidenav-menu">
                    <div className="nav">
                        <div className="sb-sidenav-menu-heading">Analysis</div>
                        <Link className="nav-link" to="/">
                            <div className="sb-nav-link-icon">
                                <FontAwesomeIcon icon={faFolder} />
                            </div>
                            Analyses
                        </Link>
                        <Link className="nav-link" to="/upload">
                            <div className="sb-nav-link-icon">
                                <FontAwesomeIcon icon={faUpload} />
                            </div>
                            Upload sample
                        </Link>
                        <div className="sb-sidenav-menu-heading">
                            Verification
                        </div>
                        <Link className="nav-link" to="/evasion">
                            <div className="sb-nav-link-icon">
                                <FontAwesomeIcon icon={faShieldHalved} />
                            </div>
                            Sandbox Evasion
                        </Link>
                        <Link className="nav-link" to="/verification-runs">
                            <div className="sb-nav-link-icon">
                                <FontAwesomeIcon icon={faClockRotateLeft} />
                            </div>
                            Verification Runs
                        </Link>
                        <div className="sb-sidenav-menu-heading">Sandbox</div>
                        <a className="nav-link" href="/openapi/swagger">
                            <div className="sb-nav-link-icon">
                                <FontAwesomeIcon icon={faGear} />
                            </div>
                            API docs
                        </a>
                        <a className="nav-link" href="/rq">
                            <div className="sb-nav-link-icon">
                                <FontAwesomeIcon icon={faGear} />
                            </div>
                            RQ Dashboard
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
    return (
        <>
            <ChimeraIntro />
            <AppHeader />
            <div id="layoutSidenav">
                <AppSidenav />
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
