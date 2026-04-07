#include "cmaper/history/internal/render_internal.h"

#include <stdio.h>

static const char *cmaper_history_device_risk_level(bool selected_present,
                                                    size_t findings_high,
                                                    size_t findings_open,
                                                    size_t surfaces) {
  if (!selected_present) {
    return "warn";
  }
  if (findings_high > 0U) {
    return "critical";
  }
  if (findings_open > 0U || surfaces > 0U) {
    return "warn";
  }
  return "ok";
}

void cmaper_history_render_devices(
    FILE *stream, const cmaper_history_render_options_t *options,
    const cmaper_history_devices_report_t *report) {
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
    fprintf(stream,
            "\"view\":\"%s\",\"db_available\":%s,\"session_found\":%s,"
            "\"session_id\":",
            cmaper_output_view_name(view),
            report->db_available ? "true" : "false",
            report->session_found ? "true" : "false");
    cmaper_history_json_string(stream, report->session_id);
    fprintf(
        stream,
        ",\"limit\":%d,\"total_devices\":%zu,\"shown\":%zu,\"truncated\":%s,",
        report->limit, report->total_devices, shown_count,
        report->truncated ? "true" : "false");
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
          ",\"host_observations\":%zu,\"open_tcp_ports\":%zu,\"findings_open\":"
          "%zu,\"findings_high_or_worse\":%zu,\"management_surfaces\":%zu",
          row->host_observations, row->open_tcp_ports, row->findings_open,
          row->findings_high_or_worse, row->management_surfaces);
      fputc('}', stream);
    }
    fputs("]}\n", stream);
    return;
  }

  if (format == CMAPER_OUTPUT_FORMAT_MARKDOWN) {
    size_t max_open = 0U;
    size_t max_high = 0U;
    size_t max_surfaces = 0U;

    fputs("# Devices\n\n## Context\n\n", stream);
    fprintf(stream, "- Database: **%s**\n",
            report->db_available ? "ready" : "missing");
    fprintf(stream, "- Session: `%s`\n", report->session_id);
    fprintf(stream, "- Requested limit: **%d**\n", report->limit);
    fprintf(stream, "- Devices available: **%zu**\n", report->total_devices);
    fprintf(stream, "- Devices shown: **%zu**\n", shown_count);

    if (!report->db_available) {
      fputs("\n## Notes\n\nNo history database found.\n", stream);
      return;
    }
    if (!report->session_found) {
      fputs("\n## Notes\n\nSession was not found in history.\n", stream);
      return;
    }

    for (i = 0; i < shown_count; ++i) {
      const cmaper_history_device_row_t *row = &report->items[i];
      if (row->findings_open > max_open) {
        max_open = row->findings_open;
      }
      if (row->findings_high_or_worse > max_high) {
        max_high = row->findings_high_or_worse;
      }
      if (row->management_surfaces > max_surfaces) {
        max_surfaces = row->management_surfaces;
      }
    }

    fputs("\n## Key Takeaways\n\n", stream);
    fprintf(stream,
            "- **Risk:** **%s** (highest per shown device: open findings "
            "**%zu**, high/critical **%zu**, surfaces **%zu**)\n",
            max_high > 0U
                ? "CRITICAL"
                : ((max_open > 0U || max_surfaces > 0U) ? "WARN" : "OK"),
            max_open, max_high, max_surfaces);
    fprintf(stream, "- Session has **%zu** tracked devices.\n",
            report->total_devices);

    fputs("\n## Details\n\n| Device | IP | Hostname | Host status | Open TCP | "
          "Open findings (high) | Surfaces |\n"
          "|---|---|---|---|---:|---:|---:|\n",
          stream);
    for (i = 0; i < shown_count; ++i) {
      const cmaper_history_device_row_t *row = &report->items[i];
      fprintf(stream, "| %s | %s | %s | %s | %zu | %zu (%zu) | %zu |\n",
              row->device_id, row->primary_ip, row->hostname, row->status,
              row->open_tcp_ports, row->findings_open,
              row->findings_high_or_worse, row->management_surfaces);
    }

    cmaper_history_render_truncated_note(stream, true, shown_count,
                                         report->count, "devices");
    return;
  }

  cmaper_history_render_heading(stream, use_ansi, "Devices");
  cmaper_history_render_section(stream, use_ansi, "Context");
  cmaper_history_render_key_value(stream, "Database",
                                  report->db_available ? "ready" : "missing");
  cmaper_history_render_key_value(stream, "Session", report->session_id);
  fprintf(stream, "  Requested limit: %d\n", report->limit);
  cmaper_history_render_key_size(stream, "Devices available",
                                 report->total_devices);
  cmaper_history_render_key_size(stream, "Devices shown", shown_count);

  if (!report->db_available) {
    cmaper_history_render_section(stream, use_ansi, "Notes");
    fputs("  No history database found.\n", stream);
    return;
  }
  if (!report->session_found) {
    cmaper_history_render_section(stream, use_ansi, "Notes");
    fputs("  Session was not found in history.\n", stream);
    return;
  }

  {
    size_t max_open = 0U;
    size_t max_high = 0U;
    size_t max_surfaces = 0U;

    for (i = 0; i < shown_count; ++i) {
      const cmaper_history_device_row_t *row = &report->items[i];
      if (row->findings_open > max_open) {
        max_open = row->findings_open;
      }
      if (row->findings_high_or_worse > max_high) {
        max_high = row->findings_high_or_worse;
      }
      if (row->management_surfaces > max_surfaces) {
        max_surfaces = row->management_surfaces;
      }
    }

    cmaper_history_render_section(stream, use_ansi, "Key Takeaways");
    cmaper_history_render_risk(
        stream, use_ansi,
        max_high > 0U ? "critical"
                      : ((max_open > 0U || max_surfaces > 0U) ? "warn" : "ok"),
        max_high > 0U ? "At least one shown device has high/critical findings."
                      : ((max_open > 0U || max_surfaces > 0U)
                             ? "Shown devices have open findings or exposed "
                               "management surfaces."
                             : "No open findings in shown devices."));
    fprintf(stream,
            "  Highest per shown device: open findings=%zu, high/critical=%zu, "
            "surfaces=%zu\n",
            max_open, max_high, max_surfaces);

    cmaper_history_render_section(stream, use_ansi, "Details");
    if (shown_count == 0U) {
      fputs("  No devices to display.\n", stream);
    }
    for (i = 0; i < shown_count; ++i) {
      const cmaper_history_device_row_t *row = &report->items[i];
      fprintf(stream,
              "  - device %s  ip=%s  status=%s  open_tcp=%zu  open "
              "findings=%zu (high=%zu)  surfaces=%zu\n",
              row->device_id, row->primary_ip, row->status, row->open_tcp_ports,
              row->findings_open, row->findings_high_or_worse,
              row->management_surfaces);
      fprintf(stream, "    hostname=%s  mac=%s\n", row->hostname,
              row->mac_address);
    }
  }

  cmaper_history_render_truncated_note(stream, false, shown_count,
                                       report->count, "devices");
}

void cmaper_history_render_device(
    FILE *stream, const cmaper_history_render_options_t *options,
    const cmaper_history_device_report_t *report) {
  size_t i;
  size_t shown_ip_count;
  size_t shown_obs_count;
  size_t shown_change_count;
  cmaper_output_format_t format;
  cmaper_output_view_t view;
  bool use_ansi;

  if (stream == NULL || report == NULL) {
    return;
  }

  format = cmaper_history_render_format(options);
  view = cmaper_history_render_view(options);
  use_ansi = cmaper_history_render_use_ansi(options);
  shown_ip_count =
      cmaper_history_render_count_for_view(report->ip_address_count, view, 8U);
  shown_obs_count =
      cmaper_history_render_count_for_view(report->observation_count, view, 8U);
  shown_change_count = cmaper_history_render_count_for_view(
      report->change_event_count, view, 12U);

  if (format == CMAPER_OUTPUT_FORMAT_JSON) {
    fputs("{\"report\":\"device\",", stream);
    fprintf(stream,
            "\"view\":\"%s\",\"db_available\":%s,\"session_found\":%s,"
            "\"found\":%s,\"selected_observation_found\":%s,",
            cmaper_output_view_name(view),
            report->db_available ? "true" : "false",
            report->session_found ? "true" : "false",
            report->found ? "true" : "false",
            report->selected_observation_found ? "true" : "false");
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
    fprintf(stream,
            ",\"selected_open_tcp_ports\":%zu,\"selected_findings_open\":%zu,"
            "\"selected_findings_high_or_worse\":%zu,\"selected_management_"
            "surfaces\":%zu",
            report->selected_open_tcp_ports, report->selected_findings_open,
            report->selected_findings_high_or_worse,
            report->selected_management_surfaces);
    fprintf(stream,
            ",\"has_window_days\":%s,\"window_days\":%d,\"changes_only\":%s,"
            "\"change_events_shown\":%zu,\"change_events_total\":%zu,"
            "\"changes_truncated\":%s",
            report->has_window_days ? "true" : "false", report->window_days,
            report->changes_only ? "true" : "false", shown_change_count,
            report->change_event_count,
            report->changes_truncated ? "true" : "false");
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
      const cmaper_history_device_observation_row_t *row =
          &report->observations[i];
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
      fprintf(stream,
              ",\"open_tcp_ports\":%zu,\"findings_open\":%zu,\"findings_high_"
              "or_worse\":%zu,\"management_surfaces\":%zu",
              row->open_tcp_ports, row->findings_open,
              row->findings_high_or_worse, row->management_surfaces);
      fputc('}', stream);
    }
    fputs("],\"change_events\":[", stream);
    for (i = 0; i < shown_change_count; ++i) {
      const cmaper_history_device_change_event_t *event =
          &report->change_events[i];
      if (i > 0U) {
        fputc(',', stream);
      }
      fputc('{', stream);
      fputs("\"session_id\":", stream);
      cmaper_history_json_string(stream, event->session_id);
      fputs(",\"started_at\":", stream);
      cmaper_history_json_string(stream, event->started_at);
      fputs(",\"event_type\":", stream);
      cmaper_history_json_string(stream, event->event_type);
      fputs(",\"detail\":", stream);
      cmaper_history_json_string(stream, event->detail);
      fputc('}', stream);
    }
    fputs("]}\n", stream);
    return;
  }

  if (format == CMAPER_OUTPUT_FORMAT_MARKDOWN) {
    fputs("# Device\n\n", stream);

    if (!report->db_available) {
      fputs("## Notes\n\nNo history database found.\n", stream);
      return;
    }
    if (!report->session_found) {
      fprintf(stream, "## Notes\n\nSession `%s` not found.\n",
              report->session_id);
      return;
    }
    if (!report->found) {
      fprintf(stream, "## Notes\n\nDevice `%s` not found.\n",
              report->device_id);
      return;
    }

    fprintf(stream, "## Context\n\n");
    fprintf(stream, "- Device: `%s`\n", report->device_id);
    fprintf(stream, "- Session: `%s`\n", report->session_id);
    fprintf(stream, "- Stable key: `%s`\n", report->stable_key);
    fprintf(stream, "- Fallback key: `%s`\n", report->fallback_key);
    fprintf(stream, "- MAC: `%s`\n", report->mac_address);
    fprintf(stream, "- Vendor: `%s`\n", report->mac_vendor);
    if (report->has_window_days) {
      fprintf(stream, "- Window: `%d day(s) before selected session`\n",
              report->window_days);
    } else {
      fprintf(stream, "- Window: `all history before selected session`\n");
    }
    fprintf(stream, "- Changes-only mode: **%s**\n",
            report->changes_only ? "yes" : "no");

    fputs("\n## Key Takeaways\n\n", stream);
    fprintf(stream, "- **Risk:** **%s**\n",
            report->selected_observation_found
                ? (report->selected_findings_high_or_worse > 0U
                       ? "CRITICAL"
                       : ((report->selected_findings_open > 0U ||
                           report->selected_management_surfaces > 0U)
                              ? "WARN"
                              : "OK"))
                : "WARN");
    if (report->selected_observation_found) {
      fprintf(stream,
              "- Selected observation: `%s` / `%s` with open findings **%zu** "
              "(high/critical **%zu**) and surfaces **%zu**\n",
              report->selected_primary_ip, report->selected_status,
              report->selected_findings_open,
              report->selected_findings_high_or_worse,
              report->selected_management_surfaces);
    } else {
      fputs("- Selected observation: device is not present in this session.\n",
            stream);
    }

    fputs("\n## Change Timeline\n\n", stream);
    if (shown_change_count == 0U) {
      fputs("- none detected in selected window\n", stream);
    } else {
      for (i = 0; i < shown_change_count; ++i) {
        const cmaper_history_device_change_event_t *event =
            &report->change_events[i];
        fprintf(stream, "- `%s` **%s**: %s\n", event->session_id,
                event->event_type, event->detail);
      }
    }
    if (shown_change_count < report->change_event_count ||
        report->changes_truncated) {
      cmaper_history_render_truncated_note(stream, true, shown_change_count,
                                           report->change_event_count,
                                           "change events");
    }

    if (report->changes_only) {
      return;
    }

    fputs("\n## Details\n\n### Selected Observation\n\n", stream);
    if (report->selected_observation_found) {
      fprintf(stream, "- IP: `%s`\n", report->selected_primary_ip);
      fprintf(stream, "- Host status: `%s`\n", report->selected_status);
      fprintf(stream, "- Hostname: `%s`\n", report->selected_hostname);
      fprintf(stream, "- Open TCP ports: **%zu**\n",
              report->selected_open_tcp_ports);
      fprintf(stream, "- Open findings (high): **%zu (%zu)**\n",
              report->selected_findings_open,
              report->selected_findings_high_or_worse);
      fprintf(stream, "- Management surfaces: **%zu**\n",
              report->selected_management_surfaces);
    } else {
      fputs("- Not present in this session.\n", stream);
    }

    fputs(
        "\n### IP History\n\n| IP | Type | Current | First seen | Last seen |\n"
        "|---|---|---|---|---|\n",
        stream);
    for (i = 0; i < shown_ip_count; ++i) {
      const cmaper_history_device_ip_row_t *row = &report->ip_addresses[i];
      fprintf(stream, "| %s | %s | %s | %s | %s |\n", row->ip_address,
              row->address_type, row->is_current ? "yes" : "no",
              row->first_seen_session_id, row->last_seen_session_id);
    }

    fputs("\n### Observations\n\n| Session | Status | IP | Host status | Open "
          "TCP | Open findings (high) | Surfaces |\n"
          "|---|---|---|---|---:|---:|---:|\n",
          stream);
    for (i = 0; i < shown_obs_count; ++i) {
      const cmaper_history_device_observation_row_t *row =
          &report->observations[i];
      fprintf(stream, "| %s | %s | %s | %s | %zu | %zu (%zu) | %zu |\n",
              row->session_id, row->status, row->primary_ip, row->host_status,
              row->open_tcp_ports, row->findings_open,
              row->findings_high_or_worse, row->management_surfaces);
    }

    if (shown_ip_count < report->ip_address_count ||
        shown_obs_count < report->observation_count) {
      fputs("\n_Notes: output is truncated (use `--view full` for full IP "
            "history and observations)._",
            stream);
      fputc('\n', stream);
    }

    fputs("\n## Next Steps\n\n", stream);
    if (!report->selected_observation_found) {
      fputs("1. Verify when this device disappeared using `timeline "
            "<session-id> <device-id>`.\n",
            stream);
      fputs(
          "2. Confirm whether disappearance is expected or a telemetry gap.\n",
          stream);
    } else if (report->selected_findings_high_or_worse > 0U) {
      fputs("1. Prioritize remediation for high/critical findings on this "
            "device.\n",
            stream);
      fputs("2. Re-scan after fixes to confirm risk reduction.\n", stream);
    } else if (report->selected_findings_open > 0U ||
               report->selected_management_surfaces > 0U) {
      fputs("1. Triage remaining open findings and exposed management "
            "surfaces.\n",
            stream);
      fputs("2. Restrict management exposure to trusted networks where "
            "possible.\n",
            stream);
    } else {
      fputs("1. Treat this state as baseline and monitor for drift in the next "
            "scan.\n",
            stream);
      fputs("2. Keep device inventory metadata current (hostname, ownership, "
            "role).\n",
            stream);
    }
    return;
  }

  cmaper_history_render_heading(stream, use_ansi, "Device");

  if (!report->db_available) {
    cmaper_history_render_section(stream, use_ansi, "Notes");
    fputs("  No history database found.\n", stream);
    return;
  }
  if (!report->session_found) {
    cmaper_history_render_section(stream, use_ansi, "Notes");
    fprintf(stream, "  Session '%s' not found.\n", report->session_id);
    return;
  }
  if (!report->found) {
    cmaper_history_render_section(stream, use_ansi, "Notes");
    fprintf(stream, "  Device '%s' not found.\n", report->device_id);
    return;
  }

  cmaper_history_render_section(stream, use_ansi, "Context");
  cmaper_history_render_key_value(stream, "Device", report->device_id);
  cmaper_history_render_key_value(stream, "Session", report->session_id);
  cmaper_history_render_key_value(stream, "Stable key", report->stable_key);
  cmaper_history_render_key_value(stream, "Fallback key", report->fallback_key);
  cmaper_history_render_key_value(stream, "MAC", report->mac_address);
  cmaper_history_render_key_value(stream, "Vendor", report->mac_vendor);
  if (report->has_window_days) {
    char window_value[64];
    (void)snprintf(window_value, sizeof(window_value),
                   "%d day(s) before selected session", report->window_days);
    cmaper_history_render_key_value(stream, "Window", window_value);
  } else {
    cmaper_history_render_key_value(stream, "Window",
                                    "all history before selected session");
  }
  cmaper_history_render_key_value(stream, "Changes-only",
                                  report->changes_only ? "yes" : "no");

  cmaper_history_render_section(stream, use_ansi, "Key Takeaways");
  cmaper_history_render_risk(
      stream, use_ansi,
      cmaper_history_device_risk_level(report->selected_observation_found,
                                       report->selected_findings_high_or_worse,
                                       report->selected_findings_open,
                                       report->selected_management_surfaces),
      !report->selected_observation_found
          ? "Device is not present in the selected session."
          : (report->selected_findings_high_or_worse > 0U
                 ? "Selected observation has high/critical findings."
                 : ((report->selected_findings_open > 0U ||
                     report->selected_management_surfaces > 0U)
                        ? "Selected observation has open findings or exposed "
                          "management surfaces."
                        : "Selected observation has no open findings.")));

  cmaper_history_render_section(stream, use_ansi, "Change Timeline");
  if (shown_change_count == 0U) {
    fputs("  No changes detected in selected window.\n", stream);
  }
  for (i = 0; i < shown_change_count; ++i) {
    const cmaper_history_device_change_event_t *event =
        &report->change_events[i];
    fprintf(stream, "  - %s [%s] %s\n", event->session_id, event->event_type,
            event->detail);
  }
  if (shown_change_count < report->change_event_count ||
      report->changes_truncated) {
    cmaper_history_render_truncated_note(stream, false, shown_change_count,
                                         report->change_event_count,
                                         "change events");
  }

  if (report->changes_only) {
    return;
  }

  cmaper_history_render_section(stream, use_ansi, "Details");
  fputs("  Selected observation:\n", stream);
  if (report->selected_observation_found) {
    fprintf(stream, "    ip=%s  host-status=%s  hostname=%s\n",
            report->selected_primary_ip, report->selected_status,
            report->selected_hostname);
    fprintf(stream,
            "    open_tcp=%zu  open findings=%zu (high=%zu)  surfaces=%zu\n",
            report->selected_open_tcp_ports, report->selected_findings_open,
            report->selected_findings_high_or_worse,
            report->selected_management_surfaces);
  } else {
    fputs("    not present in this session\n", stream);
  }

  fprintf(stream, "  IP history (%zu):\n", report->ip_address_count);
  for (i = 0; i < shown_ip_count; ++i) {
    const cmaper_history_device_ip_row_t *row = &report->ip_addresses[i];
    fprintf(stream, "    - %s (%s) current=%s first=%s last=%s\n",
            row->ip_address, row->address_type, row->is_current ? "yes" : "no",
            row->first_seen_session_id, row->last_seen_session_id);
  }

  fprintf(stream, "  Observations (%zu):\n", report->observation_count);
  for (i = 0; i < shown_obs_count; ++i) {
    const cmaper_history_device_observation_row_t *row =
        &report->observations[i];
    fprintf(stream,
            "    - %s [%s] ip=%s host-status=%s open_tcp=%zu open findings=%zu "
            "(high=%zu) surfaces=%zu\n",
            row->session_id, row->status, row->primary_ip, row->host_status,
            row->open_tcp_ports, row->findings_open,
            row->findings_high_or_worse, row->management_surfaces);
  }

  if (shown_ip_count < report->ip_address_count ||
      shown_obs_count < report->observation_count) {
    cmaper_history_render_section(stream, use_ansi, "Notes");
    fputs("  Output is truncated. Use --view full for complete IP history and "
          "observations.\n",
          stream);
  }

  cmaper_history_render_section(stream, use_ansi, "Next Steps");
  if (!report->selected_observation_found) {
    fputs("  1. Verify when this device disappeared using timeline "
          "<session-id> <device-id>.\n",
          stream);
    fputs(
        "  2. Confirm whether disappearance is expected or a telemetry gap.\n",
        stream);
  } else if (report->selected_findings_high_or_worse > 0U) {
    fputs("  1. Prioritize remediation for high/critical findings on this "
          "device.\n",
          stream);
    fputs("  2. Re-scan after fixes to verify risk reduction.\n", stream);
  } else if (report->selected_findings_open > 0U ||
             report->selected_management_surfaces > 0U) {
    fputs("  1. Triage remaining open findings and exposed management "
          "surfaces.\n",
          stream);
    fputs("  2. Restrict management exposure to trusted networks where "
          "possible.\n",
          stream);
  } else {
    fputs("  1. Treat this state as baseline and monitor for drift in the next "
          "scan.\n",
          stream);
    fputs("  2. Keep inventory metadata current (hostname, ownership, role).\n",
          stream);
  }
}
