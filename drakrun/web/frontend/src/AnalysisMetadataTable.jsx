import { PluginList } from "./PluginPicker.jsx";
import { formatDate, formatSandbox } from "./formatUtils.js";
import { formatDuration } from "./analysisTime.js";

export function AnalysisMetadataTable({ analysis }) {
    const startCommand = analysis.options["start_command"] || "-";
    const clockScale = analysis.options["clock_scale"] || 1;
    const sleepSkip = Boolean(analysis.options["sleep_skip"]);
    const shortened = analysis.time_acceleration?.delays_shortened;
    const skippedMs = analysis.time_acceleration?.delay_skipped_ms || 0;
    return (
        <table className="datatable-table">
            <tbody>
                <tr>
                    <th>File name</th>
                    <td>{analysis.file.name}</td>
                </tr>
                <tr>
                    <th>SHA256</th>
                    <td>{analysis.file.sha256}</td>
                </tr>
                <tr>
                    <th>Type</th>
                    <td>{analysis.file.type}</td>
                </tr>
                <tr>
                    <th>Sandbox</th>
                    <td>{formatSandbox(analysis)}</td>
                </tr>
                <tr>
                    <th>Start command</th>
                    <td>
                        {Array.isArray(startCommand)
                            ? startCommand.join(" ")
                            : startCommand}
                    </td>
                </tr>
                <tr>
                    <th>Analysis time</th>
                    <td>
                        {analysis.options["timeout"]} seconds
                        {clockScale > 1 &&
                            ` (guest clock ${clockScale}× faster: ${formatDuration(analysis.options["timeout"] * clockScale)} in the guest)`}
                    </td>
                </tr>
                {sleepSkip && (
                    <tr>
                        <th>Long sleeps</th>
                        <td>
                            Shortened
                            {shortened !== undefined &&
                                `: ${shortened} delay${shortened === 1 ? "" : "s"}, ${formatDuration(Math.round(skippedMs / 1000))} skipped`}
                        </td>
                    </tr>
                )}
                <tr>
                    <th>Job started at</th>
                    <td>{formatDate(analysis["time_started"])}</td>
                </tr>
                <tr>
                    <th>Execution started at</th>
                    <td>{formatDate(analysis["time_execution_started"])}</td>
                </tr>
                <tr>
                    <th>Job finished at</th>
                    <td>{formatDate(analysis["time_finished"])}</td>
                </tr>
                <tr>
                    <th>Plugins</th>
                    <td>
                        <PluginList plugins={analysis.options["plugins"]} />
                    </td>
                </tr>
            </tbody>
        </table>
    );
}
