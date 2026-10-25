import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Deliberately a separate config from vite.config.js (used for the real
// dev server / production build) so test-only concerns (jsdom environment,
// setup files) can never affect the app or embedded-report bundles.
export default defineConfig({
    plugins: [react()],
    test: {
        environment: "jsdom",
        setupFiles: ["./src/setupTests.js"],
    },
});
