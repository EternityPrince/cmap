#include "cmaper/history/render.h"

#include <stdio.h>
#include <string.h>

#include "cmaper/history/diff.h"

static cmaper_output_format_t cmaper_history_render_format(
    const cmaper_history_render_options_t *options
) {
    if (options == NULL) {
        return CMAPER_OUTPUT_FORMAT_TERMINAL;
    }
    return options->format;
}

static cmaper_output_view_t cmaper_history_render_view(
    const cmaper_history_render_options_t *options
) {
    if (options == NULL) {
        return CMAPER_OUTPUT_VIEW_COMPACT;
    }
    return options->view;
}

static bool cmaper_history_render_use_ansi(const cmaper_history_render_options_t *options) {
    return options != NULL && options->use_ansi;
}

static size_t cmaper_history_render_count_for_view(
    size_t total,
    cmaper_output_view_t view,
    size_t compact_limit
) {
    if (view == CMAPER_OUTPUT_VIEW_FULL || total <= compact_limit) {
        return total;
    }
    return compact_limit;
}

static void cmaper_history_render_heading(
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

static void cmaper_history_json_string(FILE *stream, const char *value) {
    if (stream == NULL) {
        return;
    }
    fputc('"', stream);
    if (value != NULL) {
        cmaper_history_json_escape(stream, value);
    }
    fputc('"', stream);
}

static void cmaper_history_render_reason_mask_text(FILE *stream, unsigned int mask) {
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

static void cmaper_history_render_reason_mask_json(FILE *stream, unsigned int mask) {
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

static void cmaper_history_render_alerts_text(
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

static void cmaper_history_render_alerts_json(
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

void cmaper_history_render_sessions(
    FILE *stream,
    const cmaper_history_render_options_t *options,
    const cmaper_history_sessions_report_t *report
) {
    size_t i;
    cmaper_output_format_t format;
    cmaper_output_view_t view;
    bool use_ansi;
    size_t shown_count;

    if (stream == NULL || report == NULL) {
        return;
    }

    format = cmaper_history_render_format(options);
    view = cmaper_history_render_view(options);
    use_ansi = cmaper_history_render_use_ansi(options);
    shown_count = cmaper_history_render_count_for_view(report->count, view, 10U);

    if (format == CMAPER_OUTPUT_FORMAT_JSON) {
        fputs("{\"report\":\"sessions\",", stream);
        fprintf(
            stream,
            "\"view\":\"%s\",\"db_available\":%s,\"limit\":%d,\"total_sessions\":%zu,\"shown\":%zu,\"truncated\":%s,",
            cmaper_output_view_name(view),
            report->db_available ? "true" : "false",
            report->limit,
            report->total_sessions,
            shown_count,
            report->truncated ? "true" : "false"
        );
        fputs("\"items\":[", stream);
        for (i = 0; i < shown_count; ++i) {
            const cmaper_history_session_row_t *row = &report->items[i];
            if (i > 0U) {
                fputc(',', stream);
            }
            fputc('{', stream);
            fputs("\"session_id\":", stream);
            cmaper_history_json_string(stream, row->session_id);
            fputs(",\"status\":", stream);
            cmaper_history_json_string(stream, row->status);
            fputs(",\"target\":", stream);
            cmaper_history_json_string(stream, row->target);
            fputs(",\"profile\":", stream);
            cmaper_history_json_string(stream, row->profile);
            fputs(",\"started_at\":", stream);
            cmaper_history_json_string(stream, row->started_at);
            fputs(",\"completed_at\":", stream);
            cmaper_history_json_string(stream, row->completed_at);
            fprintf(
                stream,
                ",\"host_count\":%zu,\"findings_open\":%zu,\"findings_high_or_worse\":%zu,\"management_surfaces\":%zu",
                row->host_count,
                row->findings_open,
                row->findings_high_or_worse,
                row->management_surfaces_total
            );
            fputc('}', stream);
        }
        fputs("]}\n", stream);
        return;
    }

    if (format == CMAPER_OUTPUT_FORMAT_MARKDOWN) {
        fprintf(
            stream,
            "# Sessions\n\n- Database: **%s**\n- Total: **%zu**\n- Shown: **%zu**\n- Limit: **%d**\n\n",
            report->db_available ? "ready" : "missing",
            report->total_sessions,
            shown_count,
            report->limit
        );

        if (!report->db_available) {
            fputs("No history database found.\n", stream);
            return;
        }

        fputs("| Session | Status | Target | Started | Hosts | Findings(open/high) | Surfaces |\n", stream);
        fputs("|---|---|---|---|---:|---:|---:|\n", stream);
        for (i = 0; i < shown_count; ++i) {
            const cmaper_history_session_row_t *row = &report->items[i];
            fprintf(
                stream,
                "| %s | %s | %s | %s | %zu | %zu/%zu | %zu |\n",
                row->session_id,
                row->status,
                row->target,
                row->started_at,
                row->host_count,
                row->findings_open,
                row->findings_high_or_worse,
                row->management_surfaces_total
            );
        }
        if (shown_count < report->count) {
            fprintf(stream, "\n_Compact view: showing first %zu of %zu sessions._\n", shown_count, report->count);
        }
        return;
    }

    cmaper_history_render_heading(stream, use_ansi, "Sessions");
    fprintf(
        stream,
        "Summary: db=%s total=%zu shown=%zu limit=%d%s\n",
        report->db_available ? "ready" : "missing",
        report->total_sessions,
        shown_count,
        report->limit,
        report->truncated ? " (truncated)" : ""
    );

    if (!report->db_available) {
        fputs("No history database found.\n", stream);
        return;
    }

    for (i = 0; i < shown_count; ++i) {
        const cmaper_history_session_row_t *row = &report->items[i];
        fprintf(
            stream,
            "  %s  [%s]  target=%s  started=%s  hosts=%zu  findings(open/high)=%zu/%zu  surfaces=%zu\n",
            row->session_id,
            row->status,
            row->target,
            row->started_at,
            row->host_count,
            row->findings_open,
            row->findings_high_or_worse,
            row->management_surfaces_total
        );
    }
    if (shown_count < report->count) {
        fprintf(stream, "  ... compact view: showing %zu of %zu rows (use --view full)\n", shown_count, report->count);
    }
}

void cmaper_history_render_session(
    FILE *stream,
    const cmaper_history_render_options_t *options,
    const cmaper_history_session_report_t *report
) {
    size_t i;
    size_t shown_count;
    cmaper_output_format_t format;
    cmaper_output_view_t view;
    bool use_ansi;

    if (stream == NULL || report == NULL) {
        return;
    }

    format = cmaper_history_render_format(options);
    view = cmaper_history_render_view(options);
    use_ansi = cmaper_history_render_use_ansi(options);
    shown_count = cmaper_history_render_count_for_view(report->host_count, view, 8U);

    if (format == CMAPER_OUTPUT_FORMAT_JSON) {
        fputs("{\"report\":\"session\",", stream);
        fprintf(
            stream,
            "\"view\":\"%s\",\"db_available\":%s,\"found\":%s,",
            cmaper_output_view_name(view),
            report->db_available ? "true" : "false",
            report->found ? "true" : "false"
        );
        fputs("\"session\":{", stream);
        fputs("\"session_id\":", stream);
        cmaper_history_json_string(stream, report->summary.session_id);
        fputs(",\"status\":", stream);
        cmaper_history_json_string(stream, report->summary.status);
        fputs(",\"target\":", stream);
        cmaper_history_json_string(stream, report->summary.target);
        fputs(",\"profile\":", stream);
        cmaper_history_json_string(stream, report->summary.profile);
        fputs(",\"started_at\":", stream);
        cmaper_history_json_string(stream, report->summary.started_at);
        fputs(",\"completed_at\":", stream);
        cmaper_history_json_string(stream, report->summary.completed_at);
        fprintf(
            stream,
            ",\"host_count\":%zu,\"findings_total\":%zu,\"findings_open\":%zu,\"findings_high_or_worse\":%zu,\"management_surfaces\":%zu",
            report->summary.host_count,
            report->summary.findings_total,
            report->summary.findings_open,
            report->summary.findings_high_or_worse,
            report->summary.management_surfaces_total
        );
        fputs("},\"hosts\":[", stream);
        for (i = 0; i < shown_count; ++i) {
            const cmaper_history_session_host_row_t *host = &report->hosts[i];
            if (i > 0U) {
                fputc(',', stream);
            }
            fputc('{', stream);
            fputs("\"device_id\":", stream);
            cmaper_history_json_string(stream, host->device_id);
            fputs(",\"primary_ip\":", stream);
            cmaper_history_json_string(stream, host->primary_ip);
            fputs(",\"status\":", stream);
            cmaper_history_json_string(stream, host->status);
            fputs(",\"hostname\":", stream);
            cmaper_history_json_string(stream, host->hostname);
            fputs(",\"mac_address\":", stream);
            cmaper_history_json_string(stream, host->mac_address);
            fputs(",\"mac_vendor\":", stream);
            cmaper_history_json_string(stream, host->mac_vendor);
            fprintf(
                stream,
                ",\"open_tcp_ports\":%zu,\"findings_open\":%zu,\"findings_high_or_worse\":%zu,\"management_surfaces\":%zu",
                host->open_tcp_ports,
                host->findings_open,
                host->findings_high_or_worse,
                host->management_surfaces
            );
            fputc('}', stream);
        }
        fputs("]}\n", stream);
        return;
    }

    if (format == CMAPER_OUTPUT_FORMAT_MARKDOWN) {
        if (!report->db_available) {
            fputs("# Session\n\nNo history database found.\n", stream);
            return;
        }
        if (!report->found) {
            fputs("# Session\n\nSession not found.\n", stream);
            return;
        }

        fprintf(
            stream,
            "# Session `%s`\n\n- Status: **%s**\n- Target: `%s`\n- Profile: `%s`\n- Started: `%s`\n- Completed: `%s`\n- Hosts: **%zu**\n- Findings (total/open/high): **%zu / %zu / %zu**\n- Management surfaces: **%zu**\n\n",
            report->summary.session_id,
            report->summary.status,
            report->summary.target,
            report->summary.profile,
            report->summary.started_at,
            report->summary.completed_at,
            report->summary.host_count,
            report->summary.findings_total,
            report->summary.findings_open,
            report->summary.findings_high_or_worse,
            report->summary.management_surfaces_total
        );

        fputs("| Device | IP | Status | Hostname | Open TCP | Findings(open/high) | Surfaces |\n", stream);
        fputs("|---|---|---|---|---:|---:|---:|\n", stream);
        for (i = 0; i < shown_count; ++i) {
            const cmaper_history_session_host_row_t *host = &report->hosts[i];
            fprintf(
                stream,
                "| %s | %s | %s | %s | %zu | %zu/%zu | %zu |\n",
                host->device_id,
                host->primary_ip,
                host->status,
                host->hostname,
                host->open_tcp_ports,
                host->findings_open,
                host->findings_high_or_worse,
                host->management_surfaces
            );
        }
        if (shown_count < report->host_count) {
            fprintf(stream, "\n_Compact view: showing first %zu of %zu hosts._\n", shown_count, report->host_count);
        }
        return;
    }

    if (!report->db_available) {
        fputs("Session report: no history database found.\n", stream);
        return;
    }
    if (!report->found) {
        fputs("Session report: session not found.\n", stream);
        return;
    }

    cmaper_history_render_heading(stream, use_ansi, "Session");
    fprintf(
        stream,
        "%s [%s]\nSummary: target=%s profile=%s started=%s completed=%s\n  hosts=%zu findings(total/open/high)=%zu/%zu/%zu surfaces=%zu\n",
        report->summary.session_id,
        report->summary.status,
        report->summary.target,
        report->summary.profile,
        report->summary.started_at,
        report->summary.completed_at,
        report->summary.host_count,
        report->summary.findings_total,
        report->summary.findings_open,
        report->summary.findings_high_or_worse,
        report->summary.management_surfaces_total
    );

    for (i = 0; i < shown_count; ++i) {
        const cmaper_history_session_host_row_t *host = &report->hosts[i];
        fprintf(
            stream,
            "  host device=%s ip=%s status=%s hostname=%s open_tcp=%zu findings(open/high)=%zu/%zu surfaces=%zu\n",
            host->device_id,
            host->primary_ip,
            host->status,
            host->hostname,
            host->open_tcp_ports,
            host->findings_open,
            host->findings_high_or_worse,
            host->management_surfaces
        );
    }
    if (shown_count < report->host_count) {
        fprintf(stream, "  ... compact view: showing %zu of %zu hosts (use --view full)\n", shown_count, report->host_count);
    }
}

void cmaper_history_render_devices(
    FILE *stream,
    const cmaper_history_render_options_t *options,
    const cmaper_history_devices_report_t *report
) {
    size_t i;
    size_t shown_count;
    cmaper_output_format_t format;
    cmaper_output_view_t view;
    bool use_ansi;

    if (stream == NULL || report == NULL) {
        return;
    }

    format = cmaper_history_render_format(options);
    view = cmaper_history_render_view(options);
    use_ansi = cmaper_history_render_use_ansi(options);
    shown_count = cmaper_history_render_count_for_view(report->count, view, 12U);

    if (format == CMAPER_OUTPUT_FORMAT_JSON) {
        fputs("{\"report\":\"devices\",", stream);
        fprintf(
            stream,
            "\"view\":\"%s\",\"db_available\":%s,\"session_found\":%s,\"session_id\":",
            cmaper_output_view_name(view),
            report->db_available ? "true" : "false",
            report->session_found ? "true" : "false"
        );
        cmaper_history_json_string(stream, report->session_id);
        fprintf(
            stream,
            ",\"limit\":%d,\"total_devices\":%zu,\"shown\":%zu,\"truncated\":%s,",
            report->limit,
            report->total_devices,
            shown_count,
            report->truncated ? "true" : "false"
        );
        fputs("\"items\":[", stream);
        for (i = 0; i < shown_count; ++i) {
            const cmaper_history_device_row_t *row = &report->items[i];
            if (i > 0U) {
                fputc(',', stream);
            }
            fputc('{', stream);
            fputs("\"device_id\":", stream);
            cmaper_history_json_string(stream, row->device_id);
            fputs(",\"stable_key\":", stream);
            cmaper_history_json_string(stream, row->stable_key);
            fputs(",\"fallback_key\":", stream);
            cmaper_history_json_string(stream, row->fallback_key);
            fputs(",\"mac_address\":", stream);
            cmaper_history_json_string(stream, row->mac_address);
            fputs(",\"mac_vendor\":", stream);
            cmaper_history_json_string(stream, row->mac_vendor);
            fputs(",\"primary_ip\":", stream);
            cmaper_history_json_string(stream, row->primary_ip);
            fputs(",\"hostname\":", stream);
            cmaper_history_json_string(stream, row->hostname);
            fputs(",\"status\":", stream);
            cmaper_history_json_string(stream, row->status);
            fprintf(
                stream,
                ",\"host_observations\":%zu,\"open_tcp_ports\":%zu,\"findings_open\":%zu,\"findings_high_or_worse\":%zu,\"management_surfaces\":%zu",
                row->host_observations,
                row->open_tcp_ports,
                row->findings_open,
                row->findings_high_or_worse,
                row->management_surfaces
            );
            fputc('}', stream);
        }
        fputs("]}\n", stream);
        return;
    }

    if (format == CMAPER_OUTPUT_FORMAT_MARKDOWN) {
        if (!report->db_available) {
            fputs("# Devices\n\nNo history database found.\n", stream);
            return;
        }
        if (!report->session_found) {
            fprintf(stream, "# Devices\n\nSession `%s` not found.\n", report->session_id);
            return;
        }

        fprintf(
            stream,
            "# Devices for `%s`\n\n- Total: **%zu**\n- Shown: **%zu**\n- Limit: **%d**\n\n",
            report->session_id,
            report->total_devices,
            shown_count,
            report->limit
        );
        fputs("| Device | IP | MAC | Hostname | Status | Open TCP | Findings(open/high) | Surfaces |\n", stream);
        fputs("|---|---|---|---|---|---:|---:|---:|\n", stream);
        for (i = 0; i < shown_count; ++i) {
            const cmaper_history_device_row_t *row = &report->items[i];
            fprintf(
                stream,
                "| %s | %s | %s | %s | %s | %zu | %zu/%zu | %zu |\n",
                row->device_id,
                row->primary_ip,
                row->mac_address,
                row->hostname,
                row->status,
                row->open_tcp_ports,
                row->findings_open,
                row->findings_high_or_worse,
                row->management_surfaces
            );
        }
        if (shown_count < report->count) {
            fprintf(stream, "\n_Compact view: showing first %zu of %zu devices._\n", shown_count, report->count);
        }
        return;
    }

    if (!report->db_available) {
        fputs("Devices report: no history database found.\n", stream);
        return;
    }
    if (!report->session_found) {
        fprintf(stream, "Devices report: session '%s' not found.\n", report->session_id);
        return;
    }

    cmaper_history_render_heading(stream, use_ansi, "Devices");
    fprintf(
        stream,
        "Session: %s\nSummary: total=%zu shown=%zu%s\n",
        report->session_id,
        report->total_devices,
        shown_count,
        report->truncated ? " (truncated)" : ""
    );
    for (i = 0; i < shown_count; ++i) {
        const cmaper_history_device_row_t *row = &report->items[i];
        fprintf(
            stream,
            "  device=%s ip=%s mac=%s hostname=%s open_tcp=%zu findings(open/high)=%zu/%zu surfaces=%zu\n",
            row->device_id,
            row->primary_ip,
            row->mac_address,
            row->hostname,
            row->open_tcp_ports,
            row->findings_open,
            row->findings_high_or_worse,
            row->management_surfaces
        );
    }
    if (shown_count < report->count) {
        fprintf(stream, "  ... compact view: showing %zu of %zu devices (use --view full)\n", shown_count, report->count);
    }
}

void cmaper_history_render_device(
    FILE *stream,
    const cmaper_history_render_options_t *options,
    const cmaper_history_device_report_t *report
) {
    size_t i;
    size_t shown_ip_count;
    size_t shown_obs_count;
    cmaper_output_format_t format;
    cmaper_output_view_t view;
    bool use_ansi;

    if (stream == NULL || report == NULL) {
        return;
    }

    format = cmaper_history_render_format(options);
    view = cmaper_history_render_view(options);
    use_ansi = cmaper_history_render_use_ansi(options);
    shown_ip_count = cmaper_history_render_count_for_view(report->ip_address_count, view, 8U);
    shown_obs_count = cmaper_history_render_count_for_view(report->observation_count, view, 8U);

    if (format == CMAPER_OUTPUT_FORMAT_JSON) {
        fputs("{\"report\":\"device\",", stream);
        fprintf(
            stream,
            "\"view\":\"%s\",\"db_available\":%s,\"session_found\":%s,\"found\":%s,\"selected_observation_found\":%s,",
            cmaper_output_view_name(view),
            report->db_available ? "true" : "false",
            report->session_found ? "true" : "false",
            report->found ? "true" : "false",
            report->selected_observation_found ? "true" : "false"
        );
        fputs("\"session_id\":", stream);
        cmaper_history_json_string(stream, report->session_id);
        fputs(",\"device_id\":", stream);
        cmaper_history_json_string(stream, report->device_id);
        fputs(",\"stable_key\":", stream);
        cmaper_history_json_string(stream, report->stable_key);
        fputs(",\"fallback_key\":", stream);
        cmaper_history_json_string(stream, report->fallback_key);
        fputs(",\"mac_address\":", stream);
        cmaper_history_json_string(stream, report->mac_address);
        fputs(",\"mac_vendor\":", stream);
        cmaper_history_json_string(stream, report->mac_vendor);
        fputs(",\"selected_primary_ip\":", stream);
        cmaper_history_json_string(stream, report->selected_primary_ip);
        fputs(",\"selected_hostname\":", stream);
        cmaper_history_json_string(stream, report->selected_hostname);
        fputs(",\"selected_status\":", stream);
        cmaper_history_json_string(stream, report->selected_status);
        fprintf(
            stream,
            ",\"selected_open_tcp_ports\":%zu,\"selected_findings_open\":%zu,\"selected_findings_high_or_worse\":%zu,\"selected_management_surfaces\":%zu",
            report->selected_open_tcp_ports,
            report->selected_findings_open,
            report->selected_findings_high_or_worse,
            report->selected_management_surfaces
        );
        fputs(",\"ip_addresses\":[", stream);
        for (i = 0; i < shown_ip_count; ++i) {
            const cmaper_history_device_ip_row_t *row = &report->ip_addresses[i];
            if (i > 0U) {
                fputc(',', stream);
            }
            fputc('{', stream);
            fputs("\"ip_address\":", stream);
            cmaper_history_json_string(stream, row->ip_address);
            fputs(",\"address_type\":", stream);
            cmaper_history_json_string(stream, row->address_type);
            fprintf(stream, ",\"is_current\":%s", row->is_current ? "true" : "false");
            fputs(",\"first_seen_session_id\":", stream);
            cmaper_history_json_string(stream, row->first_seen_session_id);
            fputs(",\"last_seen_session_id\":", stream);
            cmaper_history_json_string(stream, row->last_seen_session_id);
            fputc('}', stream);
        }
        fputs("],\"observations\":[", stream);
        for (i = 0; i < shown_obs_count; ++i) {
            const cmaper_history_device_observation_row_t *row = &report->observations[i];
            if (i > 0U) {
                fputc(',', stream);
            }
            fputc('{', stream);
            fputs("\"session_id\":", stream);
            cmaper_history_json_string(stream, row->session_id);
            fputs(",\"started_at\":", stream);
            cmaper_history_json_string(stream, row->started_at);
            fputs(",\"status\":", stream);
            cmaper_history_json_string(stream, row->status);
            fputs(",\"primary_ip\":", stream);
            cmaper_history_json_string(stream, row->primary_ip);
            fputs(",\"hostname\":", stream);
            cmaper_history_json_string(stream, row->hostname);
            fputs(",\"host_status\":", stream);
            cmaper_history_json_string(stream, row->host_status);
            fprintf(
                stream,
                ",\"open_tcp_ports\":%zu,\"findings_open\":%zu,\"findings_high_or_worse\":%zu,\"management_surfaces\":%zu",
                row->open_tcp_ports,
                row->findings_open,
                row->findings_high_or_worse,
                row->management_surfaces
            );
            fputc('}', stream);
        }
        fputs("]}\n", stream);
        return;
    }

    if (format == CMAPER_OUTPUT_FORMAT_MARKDOWN) {
        if (!report->db_available) {
            fputs("# Device\n\nNo history database found.\n", stream);
            return;
        }
        if (!report->session_found) {
            fprintf(stream, "# Device\n\nSession `%s` not found.\n", report->session_id);
            return;
        }
        if (!report->found) {
            fprintf(stream, "# Device\n\nDevice `%s` not found.\n", report->device_id);
            return;
        }

        fprintf(
            stream,
            "# Device `%s`\n\n- Session: `%s`\n- Stable key: `%s`\n- Fallback key: `%s`\n- MAC: `%s`\n- Vendor: `%s`\n\n",
            report->device_id,
            report->session_id,
            report->stable_key,
            report->fallback_key,
            report->mac_address,
            report->mac_vendor
        );

        if (report->selected_observation_found) {
            fprintf(
                stream,
                "## Selected observation\n\n- IP: `%s`\n- Status: `%s`\n- Hostname: `%s`\n- Open TCP: **%zu**\n- Findings(open/high): **%zu / %zu**\n- Surfaces: **%zu**\n\n",
                report->selected_primary_ip,
                report->selected_status,
                report->selected_hostname,
                report->selected_open_tcp_ports,
                report->selected_findings_open,
                report->selected_findings_high_or_worse,
                report->selected_management_surfaces
            );
        } else {
            fputs("## Selected observation\n\nNot present in this session.\n\n", stream);
        }

        fputs("## IP history\n\n| IP | Type | Current | First seen | Last seen |\n", stream);
        fputs("|---|---|---|---|---|\n", stream);
        for (i = 0; i < shown_ip_count; ++i) {
            const cmaper_history_device_ip_row_t *row = &report->ip_addresses[i];
            fprintf(
                stream,
                "| %s | %s | %s | %s | %s |\n",
                row->ip_address,
                row->address_type,
                row->is_current ? "yes" : "no",
                row->first_seen_session_id,
                row->last_seen_session_id
            );
        }

        fputs("\n## Observations\n\n| Session | Status | IP | Host status | Open TCP | Findings(open/high) | Surfaces |\n", stream);
        fputs("|---|---|---|---|---:|---:|---:|\n", stream);
        for (i = 0; i < shown_obs_count; ++i) {
            const cmaper_history_device_observation_row_t *row = &report->observations[i];
            fprintf(
                stream,
                "| %s | %s | %s | %s | %zu | %zu/%zu | %zu |\n",
                row->session_id,
                row->status,
                row->primary_ip,
                row->host_status,
                row->open_tcp_ports,
                row->findings_open,
                row->findings_high_or_worse,
                row->management_surfaces
            );
        }

        if (shown_ip_count < report->ip_address_count || shown_obs_count < report->observation_count) {
            fputs("\n_Compact view: output is truncated, use --view full._\n", stream);
        }
        return;
    }

    if (!report->db_available) {
        fputs("Device report: no history database found.\n", stream);
        return;
    }
    if (!report->session_found) {
        fprintf(stream, "Device report: session '%s' not found.\n", report->session_id);
        return;
    }
    if (!report->found) {
        fprintf(stream, "Device report: device '%s' not found.\n", report->device_id);
        return;
    }

    cmaper_history_render_heading(stream, use_ansi, "Device");
    fprintf(
        stream,
        "%s in session %s\nSummary: stable=%s fallback=%s mac=%s vendor=%s\n",
        report->device_id,
        report->session_id,
        report->stable_key,
        report->fallback_key,
        report->mac_address,
        report->mac_vendor
    );

    if (report->selected_observation_found) {
        fprintf(
            stream,
            "  selected-observation ip=%s status=%s hostname=%s open_tcp=%zu findings(open/high)=%zu/%zu surfaces=%zu\n",
            report->selected_primary_ip,
            report->selected_status,
            report->selected_hostname,
            report->selected_open_tcp_ports,
            report->selected_findings_open,
            report->selected_findings_high_or_worse,
            report->selected_management_surfaces
        );
    } else {
        fputs("  selected-observation: not present in this session\n", stream);
    }

    fprintf(stream, "  ip-history (%zu):\n", report->ip_address_count);
    for (i = 0; i < shown_ip_count; ++i) {
        const cmaper_history_device_ip_row_t *row = &report->ip_addresses[i];
        fprintf(
            stream,
            "    %s (%s) current=%s first=%s last=%s\n",
            row->ip_address,
            row->address_type,
            row->is_current ? "yes" : "no",
            row->first_seen_session_id,
            row->last_seen_session_id
        );
    }
    if (shown_ip_count < report->ip_address_count) {
        fprintf(
            stream,
            "    ... compact view: showing %zu of %zu IP rows\n",
            shown_ip_count,
            report->ip_address_count
        );
    }

    fprintf(stream, "  observations (%zu):\n", report->observation_count);
    for (i = 0; i < shown_obs_count; ++i) {
        const cmaper_history_device_observation_row_t *row = &report->observations[i];
        fprintf(
            stream,
            "    %s [%s] ip=%s host-status=%s open_tcp=%zu findings(open/high)=%zu/%zu surfaces=%zu\n",
            row->session_id,
            row->status,
            row->primary_ip,
            row->host_status,
            row->open_tcp_ports,
            row->findings_open,
            row->findings_high_or_worse,
            row->management_surfaces
        );
    }
    if (shown_obs_count < report->observation_count) {
        fprintf(
            stream,
            "    ... compact view: showing %zu of %zu observations\n",
            shown_obs_count,
            report->observation_count
        );
    }
}

void cmaper_history_render_timeline(
    FILE *stream,
    const cmaper_history_render_options_t *options,
    const cmaper_history_timeline_report_t *report
) {
    size_t i;
    size_t shown_count;
    cmaper_output_format_t format;
    cmaper_output_view_t view;
    bool use_ansi;

    if (stream == NULL || report == NULL) {
        return;
    }

    format = cmaper_history_render_format(options);
    view = cmaper_history_render_view(options);
    use_ansi = cmaper_history_render_use_ansi(options);
    shown_count = cmaper_history_render_count_for_view(report->count, view, 12U);

    if (format == CMAPER_OUTPUT_FORMAT_JSON) {
        fputs("{\"report\":\"timeline\",", stream);
        fprintf(
            stream,
            "\"view\":\"%s\",\"db_available\":%s,\"anchor_found\":%s,\"has_device_filter\":%s,\"limit\":%d,",
            cmaper_output_view_name(view),
            report->db_available ? "true" : "false",
            report->anchor_found ? "true" : "false",
            report->has_device_filter ? "true" : "false",
            report->limit
        );
        fputs("\"anchor_session_id\":", stream);
        cmaper_history_json_string(stream, report->anchor_session_id);
        fputs(",\"device_id\":", stream);
        cmaper_history_json_string(stream, report->device_id);
        fputs(",\"items\":[", stream);
        for (i = 0; i < shown_count; ++i) {
            const cmaper_history_timeline_row_t *row = &report->items[i];
            if (i > 0U) {
                fputc(',', stream);
            }
            fputc('{', stream);
            fputs("\"session_id\":", stream);
            cmaper_history_json_string(stream, row->session_id);
            fputs(",\"status\":", stream);
            cmaper_history_json_string(stream, row->status);
            fputs(",\"started_at\":", stream);
            cmaper_history_json_string(stream, row->started_at);
            fputs(",\"completed_at\":", stream);
            cmaper_history_json_string(stream, row->completed_at);
            fprintf(
                stream,
                ",\"hosts_total\":%zu,\"findings_open\":%zu,\"findings_high_or_worse\":%zu,\"management_surfaces\":%zu,\"device_present\":%s",
                row->hosts_total,
                row->findings_open,
                row->findings_high_or_worse,
                row->management_surfaces,
                row->device_present ? "true" : "false"
            );
            fputs(",\"device_ip\":", stream);
            cmaper_history_json_string(stream, row->device_ip);
            fputs(",\"device_status\":", stream);
            cmaper_history_json_string(stream, row->device_status);
            fputc('}', stream);
        }
        fputs("]}\n", stream);
        return;
    }

    if (format == CMAPER_OUTPUT_FORMAT_MARKDOWN) {
        if (!report->db_available) {
            fputs("# Timeline\n\nNo history database found.\n", stream);
            return;
        }
        if (!report->anchor_found) {
            fprintf(stream, "# Timeline\n\nAnchor session `%s` not found.\n", report->anchor_session_id);
            return;
        }

        fprintf(
            stream,
            "# Timeline for `%s`%s%s\n\n",
            report->anchor_session_id,
            report->has_device_filter ? " (device: `" : "",
            report->has_device_filter ? report->device_id : ""
        );
        if (report->has_device_filter) {
            fputs("`)\n\n", stream);
        }

        fputs("| Session | Status | Hosts | Findings(open/high) | Surfaces | Device present | Device IP |\n", stream);
        fputs("|---|---|---:|---:|---:|---|---|\n", stream);
        for (i = 0; i < shown_count; ++i) {
            const cmaper_history_timeline_row_t *row = &report->items[i];
            fprintf(
                stream,
                "| %s | %s | %zu | %zu/%zu | %zu | %s | %s |\n",
                row->session_id,
                row->status,
                row->hosts_total,
                row->findings_open,
                row->findings_high_or_worse,
                row->management_surfaces,
                row->device_present ? "yes" : "no",
                row->device_ip
            );
        }
        if (shown_count < report->count) {
            fprintf(stream, "\n_Compact view: showing first %zu of %zu timeline rows._\n", shown_count, report->count);
        }
        return;
    }

    if (!report->db_available) {
        fputs("Timeline: no history database found.\n", stream);
        return;
    }
    if (!report->anchor_found) {
        fprintf(stream, "Timeline: anchor session '%s' not found.\n", report->anchor_session_id);
        return;
    }

    cmaper_history_render_heading(stream, use_ansi, "Timeline");
    fprintf(
        stream,
        "Summary: anchor=%s%s%s shown=%zu\n",
        report->anchor_session_id,
        report->has_device_filter ? " device=" : "",
        report->has_device_filter ? report->device_id : "",
        shown_count
    );

    for (i = 0; i < shown_count; ++i) {
        const cmaper_history_timeline_row_t *row = &report->items[i];
        fprintf(
            stream,
            "  %s [%s] hosts=%zu findings(open/high)=%zu/%zu surfaces=%zu",
            row->session_id,
            row->status,
            row->hosts_total,
            row->findings_open,
            row->findings_high_or_worse,
            row->management_surfaces
        );
        if (report->has_device_filter) {
            fprintf(
                stream,
                " device_present=%s ip=%s",
                row->device_present ? "yes" : "no",
                row->device_ip
            );
        }
        fputc('\n', stream);
    }
    if (shown_count < report->count) {
        fprintf(stream, "  ... compact view: showing %zu of %zu rows (use --view full)\n", shown_count, report->count);
    }
}

void cmaper_history_render_diff(
    FILE *stream,
    const cmaper_history_render_options_t *options,
    const cmaper_history_diff_report_t *report,
    bool summary_only
) {
    size_t i;
    size_t shown_changed_count;
    bool details_enabled;
    cmaper_output_format_t format;
    cmaper_output_view_t view;
    bool use_ansi;

    if (stream == NULL || report == NULL) {
        return;
    }

    format = cmaper_history_render_format(options);
    view = cmaper_history_render_view(options);
    use_ansi = cmaper_history_render_use_ansi(options);
    details_enabled = !summary_only && view == CMAPER_OUTPUT_VIEW_FULL;
    shown_changed_count = details_enabled
        ? report->changed_host_count
        : cmaper_history_render_count_for_view(report->changed_host_count, view, 12U);

    if (format == CMAPER_OUTPUT_FORMAT_JSON) {
        fputs("{\"report\":\"diff\",", stream);
        fprintf(
            stream,
            "\"view\":\"%s\",\"db_available\":%s,\"from_found\":%s,\"to_found\":%s,\"summary_only\":%s,\"details_enabled\":%s,",
            cmaper_output_view_name(view),
            report->db_available ? "true" : "false",
            report->from_found ? "true" : "false",
            report->to_found ? "true" : "false",
            summary_only ? "true" : "false",
            details_enabled ? "true" : "false"
        );
        fputs("\"from_session_id\":", stream);
        cmaper_history_json_string(stream, report->from_session_id);
        fputs(",\"to_session_id\":", stream);
        cmaper_history_json_string(stream, report->to_session_id);
        fprintf(
            stream,
            ",\"summary\":{\"hosts_from\":%zu,\"hosts_to\":%zu,\"hosts_added\":%zu,\"hosts_removed\":%zu,\"hosts_changed\":%zu,\"hosts_moved\":%zu,\"hosts_unchanged\":%zu,"
            "\"ports_added\":%zu,\"ports_removed\":%zu,\"fingerprints_added\":%zu,\"fingerprints_removed\":%zu,"
            "\"findings_opened\":%zu,\"findings_resolved\":%zu,\"findings_high_opened\":%zu,"
            "\"management_added\":%zu,\"management_removed\":%zu}",
            report->summary.hosts_from,
            report->summary.hosts_to,
            report->summary.hosts_added,
            report->summary.hosts_removed,
            report->summary.hosts_changed,
            report->summary.hosts_moved,
            report->summary.hosts_unchanged,
            report->summary.ports_added,
            report->summary.ports_removed,
            report->summary.fingerprints_added,
            report->summary.fingerprints_removed,
            report->summary.findings_opened,
            report->summary.findings_resolved,
            report->summary.findings_high_opened,
            report->summary.management_added,
            report->summary.management_removed
        );
        fputc(',', stream);
        cmaper_history_render_alerts_json(stream, report->alerts, report->alert_count);
        fputs(",\"changed_hosts\":[", stream);
        if (!summary_only) {
            for (i = 0; i < shown_changed_count; ++i) {
                const cmaper_history_changed_host_t *row = &report->changed_hosts[i];
                if (i > 0U) {
                    fputc(',', stream);
                }
                fputc('{', stream);
                fputs("\"host_key\":", stream);
                cmaper_history_json_string(stream, row->host_key);
                fputs(",\"match_strategy\":", stream);
                cmaper_history_json_string(stream, row->match_strategy);
                fputs(",\"from_ip\":", stream);
                cmaper_history_json_string(stream, row->from_ip);
                fputs(",\"to_ip\":", stream);
                cmaper_history_json_string(stream, row->to_ip);
                fputs(",\"from_status\":", stream);
                cmaper_history_json_string(stream, row->from_status);
                fputs(",\"to_status\":", stream);
                cmaper_history_json_string(stream, row->to_status);
                fputs(",\"reasons\":", stream);
                cmaper_history_render_reason_mask_json(stream, row->reason_mask);
                fprintf(
                    stream,
                    ",\"ports_added\":%zu,\"ports_removed\":%zu,\"fingerprints_added\":%zu,\"fingerprints_removed\":%zu,"
                    "\"findings_opened\":%zu,\"findings_resolved\":%zu,\"findings_high_opened\":%zu,"
                    "\"management_added\":%zu,\"management_removed\":%zu,\"risky_surfaces_added\":%zu",
                    row->ports_added,
                    row->ports_removed,
                    row->fingerprints_added,
                    row->fingerprints_removed,
                    row->findings_opened,
                    row->findings_resolved,
                    row->findings_high_opened,
                    row->management_added,
                    row->management_removed,
                    row->risky_surfaces_added
                );
                fputc('}', stream);
            }
        }
        fputs("]}\n", stream);
        return;
    }

    if (format == CMAPER_OUTPUT_FORMAT_MARKDOWN) {
        if (!report->db_available) {
            fputs("# Diff\n\nNo history database found.\n", stream);
            return;
        }
        if (!report->from_found || !report->to_found) {
            fprintf(
                stream,
                "# Diff\n\nSession not found: from `%s` (%s), to `%s` (%s)\n",
                report->from_session_id,
                report->from_found ? "found" : "missing",
                report->to_session_id,
                report->to_found ? "found" : "missing"
            );
            return;
        }

        fprintf(
            stream,
            "# Diff `%s` -> `%s`\n\n- Hosts from/to: **%zu / %zu**\n- Added/Removed/Changed/Moved: **%zu / %zu / %zu / %zu**\n- Ports +/−: **%zu / %zu**\n- Findings opened/resolved/high-opened: **%zu / %zu / %zu**\n- Management +/−: **%zu / %zu**\n\n",
            report->from_session_id,
            report->to_session_id,
            report->summary.hosts_from,
            report->summary.hosts_to,
            report->summary.hosts_added,
            report->summary.hosts_removed,
            report->summary.hosts_changed,
            report->summary.hosts_moved,
            report->summary.ports_added,
            report->summary.ports_removed,
            report->summary.findings_opened,
            report->summary.findings_resolved,
            report->summary.findings_high_opened,
            report->summary.management_added,
            report->summary.management_removed
        );

        fputs("## Alerts\n\n", stream);
        for (i = 0; i < report->alert_count; ++i) {
            fprintf(
                stream,
                "- **%s** %s (`%s`)%s%s\n",
                report->alerts[i].severity,
                report->alerts[i].title,
                report->alerts[i].code,
                report->alerts[i].host_key[0] != '\0' ? " host=" : "",
                report->alerts[i].host_key[0] != '\0' ? report->alerts[i].host_key : ""
            );
        }
        if (report->alert_count == 0) {
            fputs("- none\n", stream);
        }

        if (!summary_only && shown_changed_count > 0) {
            fputs("\n## Changed hosts\n\n| Host | Reasons | Ports +/− | Findings +/−/high+ | Mgmt +/− |\n", stream);
            fputs("|---|---|---:|---:|---:|\n", stream);
            for (i = 0; i < shown_changed_count; ++i) {
                const cmaper_history_changed_host_t *row = &report->changed_hosts[i];
                fprintf(stream, "| %s | ", row->host_key);
                cmaper_history_render_reason_mask_text(stream, row->reason_mask);
                fprintf(
                    stream,
                    " | %zu/%zu | %zu/%zu/%zu | %zu/%zu |\n",
                    row->ports_added,
                    row->ports_removed,
                    row->findings_opened,
                    row->findings_resolved,
                    row->findings_high_opened,
                    row->management_added,
                    row->management_removed
                );
            }
            if (!details_enabled && shown_changed_count < report->changed_host_count) {
                fprintf(
                    stream,
                    "\n_Compact view: showing first %zu of %zu changed hosts._\n",
                    shown_changed_count,
                    report->changed_host_count
                );
            }
        }
        return;
    }

    if (!report->db_available) {
        fputs("Diff: no history database found.\n", stream);
        return;
    }
    if (!report->from_found || !report->to_found) {
        fprintf(
            stream,
            "Diff: session not found (from=%s found=%s, to=%s found=%s)\n",
            report->from_session_id,
            report->from_found ? "yes" : "no",
            report->to_session_id,
            report->to_found ? "yes" : "no"
        );
        return;
    }

    cmaper_history_render_heading(stream, use_ansi, "Diff");
    fprintf(
        stream,
        "Summary: %s -> %s\n  hosts from/to=%zu/%zu added=%zu removed=%zu changed=%zu moved=%zu unchanged=%zu\n"
        "  ports +%zu/-%zu fingerprints +%zu/-%zu findings opened/resolved/high-opened=%zu/%zu/%zu management +%zu/-%zu\n",
        report->from_session_id,
        report->to_session_id,
        report->summary.hosts_from,
        report->summary.hosts_to,
        report->summary.hosts_added,
        report->summary.hosts_removed,
        report->summary.hosts_changed,
        report->summary.hosts_moved,
        report->summary.hosts_unchanged,
        report->summary.ports_added,
        report->summary.ports_removed,
        report->summary.fingerprints_added,
        report->summary.fingerprints_removed,
        report->summary.findings_opened,
        report->summary.findings_resolved,
        report->summary.findings_high_opened,
        report->summary.management_added,
        report->summary.management_removed
    );

    cmaper_history_render_alerts_text(stream, report->alerts, report->alert_count);

    if (!summary_only) {
        fprintf(stream, "Changed hosts: %zu\n", report->changed_host_count);
        for (i = 0; i < shown_changed_count; ++i) {
            const cmaper_history_changed_host_t *row = &report->changed_hosts[i];
            fprintf(stream, "  %s reasons=", row->host_key);
            cmaper_history_render_reason_mask_text(stream, row->reason_mask);
            fprintf(
                stream,
                " ports +%zu/-%zu fp +%zu/-%zu findings +%zu/-%zu high+%zu mgmt +%zu/-%zu\n",
                row->ports_added,
                row->ports_removed,
                row->fingerprints_added,
                row->fingerprints_removed,
                row->findings_opened,
                row->findings_resolved,
                row->findings_high_opened,
                row->management_added,
                row->management_removed
            );
        }
        if (!details_enabled && shown_changed_count < report->changed_host_count) {
            fprintf(
                stream,
                "  ... compact view: showing %zu of %zu changed hosts (use --view full)\n",
                shown_changed_count,
                report->changed_host_count
            );
        }
    }
}

void cmaper_history_render_posture(
    FILE *stream,
    const cmaper_history_render_options_t *options,
    const cmaper_history_posture_report_t *report
) {
    cmaper_output_format_t format;
    cmaper_output_view_t view;
    bool use_ansi;

    if (stream == NULL || report == NULL) {
        return;
    }

    format = cmaper_history_render_format(options);
    view = cmaper_history_render_view(options);
    use_ansi = cmaper_history_render_use_ansi(options);

    if (format == CMAPER_OUTPUT_FORMAT_JSON) {
        fputs("{\"report\":\"posture\",", stream);
        fprintf(
            stream,
            "\"view\":\"%s\",\"db_available\":%s,\"session_found\":%s,\"has_device_filter\":%s,",
            cmaper_output_view_name(view),
            report->db_available ? "true" : "false",
            report->session_found ? "true" : "false",
            report->has_device_filter ? "true" : "false"
        );
        fputs("\"session_id\":", stream);
        cmaper_history_json_string(stream, report->session_id);
        fputs(",\"device_id\":", stream);
        cmaper_history_json_string(stream, report->device_id);
        fputs(",\"session_status\":", stream);
        cmaper_history_json_string(stream, report->session_status);
        fputs(",\"started_at\":", stream);
        cmaper_history_json_string(stream, report->started_at);
        fputs(",\"completed_at\":", stream);
        cmaper_history_json_string(stream, report->completed_at);
        fprintf(
            stream,
            ",\"counters\":{\"hosts_total\":%zu,\"hosts_up\":%zu,\"devices_total\":%zu,\"open_tcp_ports\":%zu,"
            "\"findings_total\":%zu,\"findings_open\":%zu,\"findings_high_or_worse\":%zu,"
            "\"management_surfaces_total\":%zu,\"hosts_with_management_surfaces\":%zu},",
            report->counters.hosts_total,
            report->counters.hosts_up,
            report->counters.devices_total,
            report->counters.open_tcp_ports,
            report->counters.findings_total,
            report->counters.findings_open,
            report->counters.findings_high_or_worse,
            report->counters.management_surfaces_total,
            report->counters.hosts_with_management_surfaces
        );
        fprintf(
            stream,
            "\"drift\":{\"has_previous\":%s,\"previous_session_id\":",
            report->drift.has_previous ? "true" : "false"
        );
        cmaper_history_json_string(stream, report->drift.previous_session_id);
        fprintf(
            stream,
            ",\"hosts_total_delta\":%ld,\"hosts_up_delta\":%ld,\"devices_total_delta\":%ld,"
            "\"open_tcp_ports_delta\":%ld,\"findings_total_delta\":%ld,\"findings_open_delta\":%ld,"
            "\"findings_high_or_worse_delta\":%ld,\"management_surfaces_total_delta\":%ld,"
            "\"hosts_with_management_surfaces_delta\":%ld,\"risk_increased\":%s},",
            report->drift.hosts_total_delta,
            report->drift.hosts_up_delta,
            report->drift.devices_total_delta,
            report->drift.open_tcp_ports_delta,
            report->drift.findings_total_delta,
            report->drift.findings_open_delta,
            report->drift.findings_high_or_worse_delta,
            report->drift.management_surfaces_total_delta,
            report->drift.hosts_with_management_surfaces_delta,
            report->drift.risk_increased ? "true" : "false"
        );
        cmaper_history_render_alerts_json(stream, report->alerts, report->alert_count);
        fputs("}\n", stream);
        return;
    }

    if (format == CMAPER_OUTPUT_FORMAT_MARKDOWN) {
        if (!report->db_available) {
            fputs("# Posture\n\nNo history database found.\n", stream);
            return;
        }
        if (!report->session_found) {
            fprintf(stream, "# Posture\n\nSession `%s` not found.\n", report->session_id);
            return;
        }

        fprintf(
            stream,
            "# Posture `%s`%s%s\n\n- Status: **%s**\n- Hosts total/up: **%zu / %zu**\n- Devices: **%zu**\n- Open TCP ports: **%zu**\n- Findings total/open/high: **%zu / %zu / %zu**\n- Management surfaces: **%zu** on **%zu** hosts\n\n",
            report->session_id,
            report->has_device_filter ? " (device: `" : "",
            report->has_device_filter ? report->device_id : "",
            report->session_status,
            report->counters.hosts_total,
            report->counters.hosts_up,
            report->counters.devices_total,
            report->counters.open_tcp_ports,
            report->counters.findings_total,
            report->counters.findings_open,
            report->counters.findings_high_or_worse,
            report->counters.management_surfaces_total,
            report->counters.hosts_with_management_surfaces
        );
        if (report->has_device_filter) {
            fputs("`)\n\n", stream);
        }

        if (report->drift.has_previous) {
            fprintf(
                stream,
                "## Drift vs `%s`\n\n- Hosts delta: **%+ld**\n- Open TCP delta: **%+ld**\n- Findings open delta: **%+ld**\n- Findings high delta: **%+ld**\n- Surfaces delta: **%+ld**\n- Risk increased: **%s**\n\n",
                report->drift.previous_session_id,
                report->drift.hosts_total_delta,
                report->drift.open_tcp_ports_delta,
                report->drift.findings_open_delta,
                report->drift.findings_high_or_worse_delta,
                report->drift.management_surfaces_total_delta,
                report->drift.risk_increased ? "yes" : "no"
            );
        } else {
            fputs("## Drift\n\nPrevious completed session not found.\n\n", stream);
        }

        fputs("## Alerts\n\n", stream);
        for (size_t j = 0; j < report->alert_count; ++j) {
            fprintf(
                stream,
                "- **%s** %s (`%s`)\n",
                report->alerts[j].severity,
                report->alerts[j].title,
                report->alerts[j].code
            );
        }
        if (report->alert_count == 0) {
            fputs("- none\n", stream);
        }
        return;
    }

    if (!report->db_available) {
        fputs("Posture: no history database found.\n", stream);
        return;
    }
    if (!report->session_found) {
        fprintf(stream, "Posture: session '%s' not found.\n", report->session_id);
        return;
    }

    cmaper_history_render_heading(stream, use_ansi, "Posture");
    fprintf(
        stream,
        "Summary: %s%s%s [%s]\n  hosts=%zu up=%zu devices=%zu open_tcp=%zu findings(total/open/high)=%zu/%zu/%zu surfaces=%zu hosts-with-surfaces=%zu\n",
        report->session_id,
        report->has_device_filter ? " device=" : "",
        report->has_device_filter ? report->device_id : "",
        report->session_status,
        report->counters.hosts_total,
        report->counters.hosts_up,
        report->counters.devices_total,
        report->counters.open_tcp_ports,
        report->counters.findings_total,
        report->counters.findings_open,
        report->counters.findings_high_or_worse,
        report->counters.management_surfaces_total,
        report->counters.hosts_with_management_surfaces
    );

    if (report->drift.has_previous) {
        fprintf(
            stream,
            "  drift vs %s: hosts=%+ld open_tcp=%+ld findings_open=%+ld findings_high=%+ld surfaces=%+ld risk_increased=%s\n",
            report->drift.previous_session_id,
            report->drift.hosts_total_delta,
            report->drift.open_tcp_ports_delta,
            report->drift.findings_open_delta,
            report->drift.findings_high_or_worse_delta,
            report->drift.management_surfaces_total_delta,
            report->drift.risk_increased ? "yes" : "no"
        );
    } else {
        fputs("  drift: previous completed session not found\n", stream);
    }

    cmaper_history_render_alerts_text(stream, report->alerts, report->alert_count);
}
