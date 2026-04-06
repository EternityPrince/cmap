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
    const cmaper_history_alert_t *alerts,
    size_t alert_count
) {
    size_t i;

    if (stream == NULL) {
        return;
    }

    fprintf(stream, "Alerts: %zu\n", alert_count);
    for (i = 0; i < alert_count; ++i) {
        fprintf(
            stream,
            "  - [%s] %s (%s)%s%s\n",
            alerts[i].severity,
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
