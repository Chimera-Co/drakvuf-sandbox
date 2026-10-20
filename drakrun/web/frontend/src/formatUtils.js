/**
 * Format a Date object into human-readable format.
 *
 * The date format is "2026-03-26 12:23:43".
 * For null, this function returns "-"
 *
 * @param {Date|String|null} date Date object or ISO formatted string. Can be null or an empty string.
 * @returns {String} Pretty-printed date object
 */
export function formatDate(date) {
    if (!date) {
        return "-";
    }
    if (typeof date === "string") {
        date = new Date(date);
    }
    const pad = (n) => String(n).padStart(2, "0");

    const year = date.getFullYear();
    const month = pad(date.getMonth() + 1); // Months are 0-based
    const day = pad(date.getDate());

    const hours = pad(date.getHours());
    const minutes = pad(date.getMinutes());
    const seconds = pad(date.getSeconds());

    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}

/**
 * Create a Date object from Unix timestamp
 *
 * @param {number} timestamp Unix timestmap
 * @returns {Date}
 */
export function fromTimestamp(timestamp) {
    return new Date(timestamp * 1000);
}

const GUEST_OS_LABELS = { windows: "Windows 10", linux: "Debian 12 (Linux)" };

/**
 * Which sandbox an analysis ran in, e.g. "Windows 10 · vm-1" or "Debian 12 (Linux) · vm-2".
 * Analyses from before the Linux sandbox have no guest_os and ran on Windows.
 *
 * @param {Object} analysis Analysis metadata (options.guest_os, vm_id)
 * @returns {String}
 */
export function formatSandbox(analysis) {
    const os = analysis.options?.guest_os || "windows";
    const label = GUEST_OS_LABELS[os] || os;
    return analysis.vm_id != null ? `${label} · vm-${analysis.vm_id}` : label;
}
