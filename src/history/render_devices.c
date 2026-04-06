#include "cmaper/history/internal/render_internal.h"

#include <stdio.h>

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

