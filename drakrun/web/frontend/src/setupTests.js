import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";

// vitest.config.js runs with test.globals disabled (deliberately - see that
// file), so @testing-library/react's automatic afterEach(cleanup) hook,
// which only registers itself when it finds a global afterEach, never
// fires on its own. Without this, a component rendered in one test stays
// mounted into the next test in the same file.
afterEach(() => {
    cleanup();
});
