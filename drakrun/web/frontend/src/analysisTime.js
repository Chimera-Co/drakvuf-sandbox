// Analysis time choices and arithmetic for the upload form (AnalysisTimeOptions.jsx).

// Guest time the sample should live through, in minutes
export const TIME_PRESETS_MIN = [5, 10, 20, 30, 60, 120, 240, 600, 1440];
export const MAX_CUSTOM_MIN = 1440;
// Clock speed-up factors offered (the server accepts 1..analysis_time.clock_scale_max)
export const CLOCK_FACTORS = [6, 12, 30, 60];
export const DEFAULT_FACTOR = 12;
// The VM always runs at least this long, however fast its clock
const MIN_REAL_S = 60;

export function formatDuration(seconds) {
    if (seconds < 60) return `${seconds} s`;
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.round((seconds % 3600) / 60);
    if (!hours) return `${minutes} min`;
    return minutes ? `${hours} h ${minutes} min` : `${hours} h`;
}

// Real seconds the VM runs to cover guestMinutes when its clock runs clockScale times faster
export function realTimeoutSeconds(guestMinutes, clockScale) {
    return Math.max(MIN_REAL_S, Math.ceil((guestMinutes * 60) / clockScale));
}
