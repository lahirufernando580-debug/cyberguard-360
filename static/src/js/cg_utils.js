import { browser } from "@web/core/browser/browser";
import { deserializeDateTime } from "@web/core/l10n/dates";

const THEME_KEY = "cyberguard_360.theme";

export function loadTheme() {
    return browser.localStorage.getItem(THEME_KEY) === "light" ? "light" : "dark";
}

export function saveTheme(theme) {
    browser.localStorage.setItem(THEME_KEY, theme);
}

/** Server datetimes are UTC strings; show them in the user's timezone. */
export function formatTime(value, format = "dd LLL, HH:mm") {
    if (!value) {
        return "";
    }
    try {
        return deserializeDateTime(value).toFormat(format);
    } catch {
        return value;
    }
}

export function relativeTime(value) {
    if (!value) {
        return "";
    }
    try {
        return deserializeDateTime(value).toRelative() || "";
    } catch {
        return value;
    }
}

/**
 * Turn lightweight markdown (bold and dash lists) into a structure the template
 * can render without injecting HTML: [{ bullet, parts: [{ bold, text }] }].
 */
export function parseRichText(text) {
    return (text || "")
        .split("\n")
        .filter((line) => line.trim().length)
        .map((line) => {
            const trimmed = line.trim();
            const bullet = /^[-*•]\s+/.test(trimmed);
            const body = bullet ? trimmed.replace(/^[-*•]\s+/, "") : trimmed;
            const parts = body
                .split(/(\*\*[^*]+\*\*)/g)
                .filter((part) => part.length)
                .map((part) =>
                    part.startsWith("**") && part.endsWith("**")
                        ? { bold: true, text: part.slice(2, -2) }
                        : { bold: false, text: part }
                );
            return { bullet, parts };
        });
}

export const SEVERITIES = ["critical", "high", "medium", "low"];

export function scoreLevel(score) {
    if (score > 16) {
        return "critical";
    }
    if (score > 9) {
        return "high";
    }
    if (score > 4) {
        return "medium";
    }
    return "low";
}

export function listAction(name, resModel, domain = [], context = {}) {
    return {
        type: "ir.actions.act_window",
        name,
        res_model: resModel,
        views: [
            [false, "list"],
            [false, "form"],
        ],
        domain,
        context,
        target: "current",
    };
}

export function formAction(resModel, resId) {
    return {
        type: "ir.actions.act_window",
        res_model: resModel,
        res_id: resId,
        views: [[false, "form"]],
        target: "current",
    };
}
