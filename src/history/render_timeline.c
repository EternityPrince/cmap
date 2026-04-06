#include "cmaper/history/internal/render_internal.h"

#include <stdio.h>

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

