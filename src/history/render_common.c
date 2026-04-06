#include "cmaper/history/internal/render_internal.h"

#include <stdio.h>
#include <string.h>

#include "cmaper/history/diff.h"

cmaper_output_format_t cmaper_history_render_format(
    const cmaper_history_render_options_t *options
) {
    if (options == NULL) {
        return CMAPER_OUTPUT_FORMAT_TERMINAL;
    }
    return options->format;
}

cmaper_output_view_t cmaper_history_render_view(
    const cmaper_history_render_options_t *options
) {
    if (options == NULL) {
        return CMAPER_OUTPUT_VIEW_COMPACT;
    }
    return options->view;
}

bool cmaper_history_render_use_ansi(const cmaper_history_render_options_t *options) {
    return options != NULL && options->use_ansi;
}

size_t cmaper_history_render_count_for_view(
    size_t total,
    cmaper_output_view_t view,
    size_t compact_limit
) {
    if (view == CMAPER_OUTPUT_VIEW_FULL || total <= compact_limit) {
        return total;
    }
    return compact_limit;
}

void cmaper_history_render_heading(
    FILE *stream,
    bool use_ansi,
    const char *title
) {
    if (stream == NULL || title == NULL) {
        return;
    }

    if (use_ansi) {
        fprintf(stream, "\033[1;36m%s\033[0m\n", title);
    } else {
        fprintf(stream, "%s\n", title);
    }
}

void cmaper_history_render_section(
    FILE *stream,
    bool use_ansi,
    const char *title
) {
    if (stream == NULL || title == NULL) {
        return;
    }

    if (use_ansi) {
        fprintf(stream, "\n\033[1;34m%s\033[0m\n", title);
    } else {
        fprintf(stream, "\n%s\n", title);
    }
}

void cmaper_history_render_key_value(FILE *stream, const char *label, const char *value) {
    if (stream == NULL || label == NULL) {
        return;
    }

    fprintf(stream, "  %s: %s\n", label, value != NULL && value[0] != '\0' ? value : "-");
}

void cmaper_history_render_key_size(FILE *stream, const char *label, size_t value) {
    if (stream == NULL || label == NULL) {
        return;
    }

    fprintf(stream, "  %s: %zu\n", label, value);
}

void cmaper_history_render_key_signed(FILE *stream, bool use_ansi, const char *label, long value) {
    const char *color = "\033[1;37m";

    if (stream == NULL || label == NULL) {
        return;
    }

    if (value > 0) {
        color = "\033[1;33m";
    } else if (value < 0) {
        color = "\033[1;32m";
    }

    if (use_ansi) {
        fprintf(stream, "  %s: %s%+ld\033[0m\n", label, color, value);
    } else {
        fprintf(stream, "  %s: %+ld\n", label, value);
    }
}

static bool cmaper_history_render_level_is(const char *level, const char *expected) {
    if (level == NULL || expected == NULL) {
        return false;
    }
    return strcmp(level, expected) == 0;
}

static const char *cmaper_history_render_level_text(const char *level) {
    if (cmaper_history_render_level_is(level, "critical")) {
        return "CRITICAL";
    }
    if (cmaper_history_render_level_is(level, "high")) {
        return "HIGH";
    }
    if (cmaper_history_render_level_is(level, "warn")) {
        return "WARN";
    }
    if (cmaper_history_render_level_is(level, "ok")) {
        return "OK";
    }
    return "INFO";
}

static const char *cmaper_history_render_level_color(const char *level) {
    if (cmaper_history_render_level_is(level, "critical")) {
        return "\033[1;31m";
    }
    if (cmaper_history_render_level_is(level, "high")) {
        return "\033[38;5;208m";
    }
    if (cmaper_history_render_level_is(level, "warn")) {
        return "\033[1;33m";
    }
    if (cmaper_history_render_level_is(level, "ok")) {
        return "\033[1;32m";
    }
    return "\033[1;36m";
}

static void cmaper_history_render_badge(
    FILE *stream,
    bool use_ansi,
    const char *level,
    const char *text
) {
    if (stream == NULL || text == NULL) {
        return;
    }

    if (use_ansi) {
        fprintf(
            stream,
            "%s[%s]\033[0m",
            cmaper_history_render_level_color(level),
            text
        );
    } else {
        fprintf(stream, "[%s]", text);
    }
}

void cmaper_history_render_risk(
    FILE *stream,
    bool use_ansi,
    const char *level,
    const char *summary
) {
    if (stream == NULL) {
        return;
    }

    fputs("  Risk: ", stream);
    cmaper_history_render_badge(stream, use_ansi, level, cmaper_history_render_level_text(level));
    fprintf(stream, " %s\n", summary != NULL && summary[0] != '\0' ? summary : "No additional context.");
}

void cmaper_history_render_truncated_note(
    FILE *stream,
    bool markdown,
    size_t shown,
    size_t total,
    const char *subject
) {
    const char *item_label = subject != NULL && subject[0] != '\0' ? subject : "rows";

    if (stream == NULL || shown >= total) {
        return;
    }

    if (markdown) {
        fprintf(
            stream,
            "\n_Notes: showing first %zu of %zu %s (use `--view full` for the full report)._\n",
            shown,
            total,
            item_label
        );
    } else {
        fputs("\nNotes\n", stream);
        fprintf(
            stream,
            "  Showing first %zu of %zu %s. Use --view full for the complete report.\n",
            shown,
            total,
            item_label
        );
    }
}

static void cmaper_history_json_escape(FILE *stream, const char *value) {
    size_t i;

    if (stream == NULL) {
        return;
    }

    if (value == NULL) {
        return;
    }

    for (i = 0; value[i] != '\0'; ++i) {
        unsigned char ch = (unsigned char) value[i];
        switch (ch) {
        case '"':
            fputs("\\\"", stream);
            break;
        case '\\':
            fputs("\\\\", stream);
            break;
        case '\n':
            fputs("\\n", stream);
            break;
        case '\r':
            fputs("\\r", stream);
            break;
        case '\t':
            fputs("\\t", stream);
            break;
        default:
            if (ch < 32U) {
                fprintf(stream, "\\u%04x", (unsigned int) ch);
            } else {
                fputc((int) ch, stream);
            }
            break;
        }
    }
}

void cmaper_history_json_string(FILE *stream, const char *value) {
    if (stream == NULL) {
        return;
    }
    fputc('"', stream);
    if (value != NULL) {
        cmaper_history_json_escape(stream, value);
    }
    fputc('"', stream);
}

void cmaper_history_render_reason_mask_text(FILE *stream, unsigned int mask) {
    static const cmaper_history_host_reason_t REASONS[] = {
        CMAPER_HISTORY_HOST_REASON_ADDED,
        CMAPER_HISTORY_HOST_REASON_REMOVED,
        CMAPER_HISTORY_HOST_REASON_MOVED,
        CMAPER_HISTORY_HOST_REASON_STATUS_CHANGED,
        CMAPER_HISTORY_HOST_REASON_HOSTNAME_CHANGED,
        CMAPER_HISTORY_HOST_REASON_MAC_CHANGED,
        CMAPER_HISTORY_HOST_REASON_PORTS_CHANGED,
        CMAPER_HISTORY_HOST_REASON_FINGERPRINTS_CHANGED,
        CMAPER_HISTORY_HOST_REASON_FINDINGS_CHANGED,
        CMAPER_HISTORY_HOST_REASON_MANAGEMENT_CHANGED
    };
    size_t i;
    bool first = true;

    if (stream == NULL) {
        return;
    }

    for (i = 0; i < sizeof(REASONS) / sizeof(REASONS[0]); ++i) {
        if (!cmaper_history_host_reason_has(mask, REASONS[i])) {
            continue;
        }
        if (!first) {
            fputs(",", stream);
        }
        fputs(cmaper_history_host_reason_name(REASONS[i]), stream);
        first = false;
    }

    if (first) {
        fputs("none", stream);
    }
}

void cmaper_history_render_reason_mask_json(FILE *stream, unsigned int mask) {
    static const cmaper_history_host_reason_t REASONS[] = {
        CMAPER_HISTORY_HOST_REASON_ADDED,
        CMAPER_HISTORY_HOST_REASON_REMOVED,
        CMAPER_HISTORY_HOST_REASON_MOVED,
        CMAPER_HISTORY_HOST_REASON_STATUS_CHANGED,
        CMAPER_HISTORY_HOST_REASON_HOSTNAME_CHANGED,
        CMAPER_HISTORY_HOST_REASON_MAC_CHANGED,
        CMAPER_HISTORY_HOST_REASON_PORTS_CHANGED,
        CMAPER_HISTORY_HOST_REASON_FINGERPRINTS_CHANGED,
        CMAPER_HISTORY_HOST_REASON_FINDINGS_CHANGED,
        CMAPER_HISTORY_HOST_REASON_MANAGEMENT_CHANGED
    };
    size_t i;
    bool first = true;

    if (stream == NULL) {
        return;
    }

    fputc('[', stream);
    for (i = 0; i < sizeof(REASONS) / sizeof(REASONS[0]); ++i) {
        if (!cmaper_history_host_reason_has(mask, REASONS[i])) {
            continue;
        }
        if (!first) {
            fputc(',', stream);
        }
        cmaper_history_json_string(stream, cmaper_history_host_reason_name(REASONS[i]));
        first = false;
    }
    fputc(']', stream);
}

void cmaper_history_render_alerts_text(
    FILE *stream,
    bool use_ansi,
    const cmaper_history_alert_t *alerts,
    size_t alert_count
) {
    size_t i;

    if (stream == NULL) {
        return;
    }

    fprintf(stream, "  Total alerts: %zu\n", alert_count);
    if (alert_count == 0U) {
        fputs("  - none\n", stream);
        return;
    }

    for (i = 0; i < alert_count; ++i) {
        const char *level = alerts[i].severity;
        fputs("  - ", stream);
        cmaper_history_render_badge(stream, use_ansi, level, cmaper_history_render_level_text(level));
        fprintf(
            stream,
            " %s (%s)%s%s\n",
            alerts[i].title,
            alerts[i].code,
            alerts[i].host_key[0] != '\0' ? " host=" : "",
            alerts[i].host_key[0] != '\0' ? alerts[i].host_key : ""
        );
    }
}

void cmaper_history_render_alerts_json(
    FILE *stream,
    const cmaper_history_alert_t *alerts,
    size_t alert_count
) {
    size_t i;

    if (stream == NULL) {
        return;
    }

    fputs("\"alerts\":[", stream);
    for (i = 0; i < alert_count; ++i) {
        if (i > 0U) {
            fputc(',', stream);
        }
        fputc('{', stream);
        fputs("\"severity\":", stream);
        cmaper_history_json_string(stream, alerts[i].severity);
        fputs(",\"code\":", stream);
        cmaper_history_json_string(stream, alerts[i].code);
        fputs(",\"title\":", stream);
        cmaper_history_json_string(stream, alerts[i].title);
        fputs(",\"detail\":", stream);
        cmaper_history_json_string(stream, alerts[i].detail);
        fputs(",\"host_key\":", stream);
        cmaper_history_json_string(stream, alerts[i].host_key);
        fputc('}', stream);
    }
    fputc(']', stream);
}
