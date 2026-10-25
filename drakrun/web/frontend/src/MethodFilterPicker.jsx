import { useCallback, useMemo } from "react";
import CreatableSelect from "react-select/creatable";
import { selectStyles } from "./themes.js";

const methodPickerStyles = selectStyles({
    multiValue: (styles) => ({
        ...styles,
        backgroundColor: "rgba(var(--chimera-orange-rgb), 0.14)",
    }),
    multiValueLabel: (styles) => ({
        ...styles,
        color: "var(--chimera-orange-ink)",
    }),
});

export function MethodFilterPicker({ onFilterChange, methods, currentFilter }) {
    const onSelectChange = useCallback(
        (value) => {
            return onFilterChange(value.map((v) => v.value));
        },
        [onFilterChange],
    );
    const methodOptions = useMemo(
        () => methods.map((option) => ({ label: option, value: option })),
        [methods],
    );
    const currentFilterOptions = useMemo(
        () => currentFilter.map((option) => ({ label: option, value: option })),
        [currentFilter],
    );
    return (
        <div>
            <CreatableSelect
                isMulti
                options={methodOptions}
                value={currentFilterOptions}
                styles={methodPickerStyles}
                onChange={onSelectChange}
            />
        </div>
    );
}
