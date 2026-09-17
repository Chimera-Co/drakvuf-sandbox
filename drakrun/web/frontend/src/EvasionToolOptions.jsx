import Select from "react-select";

/**
 * Renders one tool's Custom-profile configuration panel entirely from the
 * options_schema object GET /api/evasion/tools (or /sandboxes) returned for
 * it - no tool id or option name is ever special-cased here. A tool whose
 * schema says full_suite_only=true (PERDEDOR today) gets an explanatory
 * note instead of fabricated checkboxes, because it genuinely has no
 * per-check selection to offer. A tool with real options (al-khaser today)
 * gets one control per schema entry, dispatched purely on "kind" - adding a
 * check type, or a whole new tool, never requires a change here as long as
 * it reuses one of the kinds already handled (or degrades gracefully to the
 * text fallback below, which is honest about not recognizing it rather than
 * silently dropping the option).
 */

function MultiselectOption({ field, value, onChange }) {
    const choices = field.choices || [];
    const selected = Array.isArray(value) ? value : field.default || [];
    const options = choices.map((choice) => ({ value: choice, label: choice }));
    const selectedOptions = options.filter((o) => selected.includes(o.value));

    return (
        <div className="mb-3">
            <label className="form-label">{field.label}</label>
            <Select
                isMulti
                options={options}
                value={selectedOptions}
                onChange={(picked) =>
                    onChange((picked || []).map((o) => o.value))
                }
                classNamePrefix="evasion-select"
            />
            {field.note ? <div className="form-text">{field.note}</div> : []}
        </div>
    );
}

function IntegerOption({ field, value, onChange }) {
    const current = typeof value === "number" ? value : field.default;
    return (
        <div className="mb-3">
            <label className="form-label">{field.label}</label>
            <input
                type="number"
                className="form-control"
                min={field.minimum}
                value={current}
                onChange={(ev) => onChange(parseInt(ev.target.value, 10))}
            />
            {field.note ? <div className="form-text">{field.note}</div> : []}
        </div>
    );
}

function TextFallbackOption({ field, value, onChange }) {
    const current = typeof value === "string" ? value : (field.default ?? "");
    return (
        <div className="mb-3">
            <label className="form-label">{field.label}</label>
            <input
                type="text"
                className="form-control"
                value={current}
                onChange={(ev) => onChange(ev.target.value)}
            />
            <div className="form-text text-warning">
                This option's kind (&quot;{field.kind}&quot;) isn&apos;t
                recognized by this UI yet, so it is shown as free text.
            </div>
            {field.note ? <div className="form-text">{field.note}</div> : []}
        </div>
    );
}

export function EvasionToolOptions({ tool, value, onChange }) {
    const schema = tool.options_schema;
    const currentValue = value || {};

    const setField = (name, fieldValue) => {
        onChange({ ...currentValue, [name]: fieldValue });
    };

    if (!schema || schema.full_suite_only || schema.options.length === 0) {
        return (
            <div className="text-muted small">
                {tool.display_name} runs its full check suite; it has no
                per-check configuration to customize.
            </div>
        );
    }

    return (
        <div>
            {schema.options.map((field) => {
                const fieldValue = currentValue[field.name];
                const setValue = (v) => setField(field.name, v);
                if (field.kind === "multiselect") {
                    return (
                        <MultiselectOption
                            key={field.name}
                            field={field}
                            value={fieldValue}
                            onChange={setValue}
                        />
                    );
                }
                if (field.kind === "integer") {
                    return (
                        <IntegerOption
                            key={field.name}
                            field={field}
                            value={fieldValue}
                            onChange={setValue}
                        />
                    );
                }
                return (
                    <TextFallbackOption
                        key={field.name}
                        field={field}
                        value={fieldValue}
                        onChange={setValue}
                    />
                );
            })}
        </div>
    );
}
