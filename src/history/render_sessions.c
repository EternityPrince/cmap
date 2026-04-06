#include "cmaper/history/internal/render_internal.h"

#include <stdio.h>

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

