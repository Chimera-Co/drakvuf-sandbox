import { useCallback, useState } from "react";
import CreatableSelect from "react-select/creatable";
import { selectStyles } from "./themes.js";

const createOption = (option) => ({ label: option, value: option });

const plugins = [
    createOption("apimon"),
    createOption("bsodmon"),
    createOption("clipboardmon"),
    createOption("codemon"),
    createOption("delaymon"),
    createOption("exmon"),
    createOption("fileextractor"),
    createOption("filetracer"),
    createOption("hidevm"),
    createOption("hidsim"),
    createOption("ipt"),
    createOption("memdump"),
    createOption("objmon"),
    createOption("procmon"),
    createOption("regmon"),
    createOption("socketmon"),
    createOption("syscalls"),
    createOption("tlsmon"),
    createOption("windowmon"),
];

const defaultPlugins = [
    createOption("apimon"),
    createOption("filetracer"),
    createOption("memdump"),
    createOption("procmon"),
    createOption("socketmon"),
    createOption("tlsmon"),
];

const linuxDefaultPlugins = [
    "procmon",
    "syscalls",
    "filetracer",
    "unixsocketmon",
    "ptracemon",
    "ebpfmon",
].map(createOption);

const linuxPlugins = [
    ...linuxDefaultPlugins,
    ...["cpuidmon", "rebootmon", "debugmon", "procdump2"].map(createOption),
];

// Plugins typed in by hand (not in the list) are shown in orange.
const pluginPickerStyles = selectStyles({
    multiValue: (styles, { data }) =>
        data.__isNew__
            ? {
                  ...styles,
                  backgroundColor: "rgba(var(--chimera-orange-rgb), 0.14)",
              }
            : styles,
    multiValueLabel: (styles, { data }) =>
        data.__isNew__
            ? { ...styles, color: "var(--chimera-orange-ink)" }
            : styles,
});

export function PluginList({ plugins }) {
    return (
        <div className="d-flex flex-wrap flex-row">
            {plugins.map((plugin) => (
                <div
                    className="plugin-badge"
                    style={{
                        backgroundColor:
                            "rgba(var(--chimera-accent-rgb), 0.14)",
                        color: "var(--chimera-accent-ink)",
                    }}
                    key={plugin}
                >
                    {plugin}
                </div>
            ))}
        </div>
    );
}

export function PluginPicker({ onChange, name, guestOs = "windows" }) {
    const [warning, setWarning] = useState(undefined);
    const onSelectChange = useCallback(
        (currentValue) => {
            if (currentValue.some((data) => data.__isNew__)) {
                setWarning(
                    "Picked custom plugin which may be not supported by CHIMERA",
                );
            } else if (
                currentValue.length > 0 &&
                !currentValue.some((data) => data.value === "procmon")
            ) {
                setWarning(
                    "It's recommended to include 'procmon' plugin for complete process information",
                );
            } else {
                setWarning(undefined);
            }
            if (onChange) onChange(currentValue);
        },
        [onChange],
    );
    return (
        <div>
            <CreatableSelect
                isMulti
                options={guestOs === "linux" ? linuxPlugins : plugins}
                isValidNewOption={guestOs === "linux" ? () => false : undefined}
                styles={pluginPickerStyles}
                onChange={onSelectChange}
                defaultValue={
                    guestOs === "linux" ? linuxDefaultPlugins : defaultPlugins
                }
                name={name}
            />
            {warning ? <div className="text-danger small">{warning}</div> : []}
        </div>
    );
}
