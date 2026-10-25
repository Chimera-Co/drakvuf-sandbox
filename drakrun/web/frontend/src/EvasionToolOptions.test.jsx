import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { EvasionToolOptions } from "./EvasionToolOptions.jsx";

describe("EvasionToolOptions", () => {
    it("renders no controls for a full_suite_only tool, only an explanatory note", () => {
        const tool = {
            id: "perdedor",
            display_name: "PERDEDOR",
            options_schema: { full_suite_only: true, options: [] },
        };
        render(
            <EvasionToolOptions tool={tool} value={{}} onChange={vi.fn()} />,
        );

        expect(
            screen.getByText(/runs its full check suite/i),
        ).toBeInTheDocument();
        expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
        expect(screen.queryByRole("spinbutton")).not.toBeInTheDocument();
    });

    it("renders exactly the controls the schema declares, and nothing invented", () => {
        const tool = {
            id: "alkhaser",
            display_name: "al-khaser",
            options_schema: {
                full_suite_only: false,
                options: [
                    {
                        name: "checks",
                        kind: "multiselect",
                        label: "Check categories",
                        choices: ["DEBUG", "VBOX", "CODE_INJECTIONS"],
                        default: ["DEBUG", "VBOX"],
                        note: "CODE_INJECTIONS is not part of the default suite.",
                    },
                    {
                        name: "sleep_seconds",
                        kind: "integer",
                        label: "Timing-attack sleep duration (seconds)",
                        default: 30,
                        minimum: 1,
                    },
                ],
            },
        };
        render(
            <EvasionToolOptions tool={tool} value={{}} onChange={vi.fn()} />,
        );

        expect(screen.getByText("Check categories")).toBeInTheDocument();
        expect(
            screen.getByText(
                /CODE_INJECTIONS is not part of the default suite/,
            ),
        ).toBeInTheDocument();
        const sleepInput = screen.getByRole("spinbutton");
        expect(sleepInput).toHaveValue(30);
        expect(sleepInput).toHaveAttribute("min", "1");
        // No option kind other than the two declared above should ever
        // produce a checkbox - that would be an invented control.
        expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
    });

    it("shows an honest fallback (not a silently dropped option) for an unrecognized kind", () => {
        const tool = {
            id: "future-tool",
            display_name: "Future Tool",
            options_schema: {
                full_suite_only: false,
                options: [
                    {
                        name: "mystery_option",
                        kind: "some-future-kind",
                        label: "Mystery option",
                        default: "x",
                    },
                ],
            },
        };
        render(
            <EvasionToolOptions tool={tool} value={{}} onChange={vi.fn()} />,
        );

        expect(screen.getByText("Mystery option")).toBeInTheDocument();
        expect(screen.getByDisplayValue("x")).toBeInTheDocument();
        expect(
            screen.getByText(/isn't recognized by this UI yet/),
        ).toBeInTheDocument();
    });
});
