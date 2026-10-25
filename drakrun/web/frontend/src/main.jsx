import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "bootstrap";
import "bootstrap/dist/css/bootstrap.css";

import App from "./App.jsx";
import { initTheme } from "./themes.js";
import { BrowserRouter } from "react-router-dom";

// Before the first render, so a dark theme never flashes light.
initTheme();

createRoot(document.getElementById("root")).render(
    <StrictMode>
        <BrowserRouter>
            <App />
        </BrowserRouter>
    </StrictMode>,
);
