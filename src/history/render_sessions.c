#include "cmaper/history/internal/render_internal.h"

#include <stdio.h>
#include <string.h>

static const char *cmaper_history_findings_risk_level(size_t high_findings,
                                                      size_t open_findings) {
  if (high_findings > 0U) {
    return "critical";
  }
  if (open_findings > 0U) {
    return "warn";
  }
  return "ok";
}

static void cmaper_history_copy_text_range(char *out, size_t out_cap,
                                           const char *start, size_t len) {
  if (out == NULL || out_cap == 0U) {
    return;
  }
  if (start == NULL) {
    out[0] = '\0';
    return;
  }
  if (len >= out_cap) {
    len = out_cap - 1U;
  }
  if (len > 0U) {
    memcpy(out, start, len);
  }
  out[len] = '\0';
}

static bool cmaper_history_script_row_next(const char **cursor, char *line,
                                           size_t line_cap) {
  const char *start;
  const char *end;
  size_t len;

  if (cursor == NULL || *cursor == NULL || line == NULL || line_cap == 0U) {
    return false;
  }

  start = *cursor;
  if (start[0] == '\0') {
    return false;
  }

  end = strchr(start, '\n');
  len = end != NULL ? (size_t)(end - start) : strlen(start);
  cmaper_history_copy_text_range(line, line_cap, start, len);
  *cursor = end != NULL ? (end + 1) : (start + len);
  return true;
}

static void cmaper_history_script_row_decode(const char *row, char *script,
                                             size_t script_cap, char *target,
                                             size_t target_cap, char *result,
                                             size_t result_cap) {
  const char *tab1;
  const char *tab2;

  if (script != NULL && script_cap > 0U) {
    (void)snprintf(script, script_cap, "-");
  }
  if (target != NULL && target_cap > 0U) {
    (void)snprintf(target, target_cap, "-");
  }
  if (result != NULL && result_cap > 0U) {
    (void)snprintf(result, result_cap, "-");
  }

  if (row == NULL || row[0] == '\0') {
    return;
  }

  tab1 = strchr(row, '\t');
  if (tab1 == NULL) {
    if (script != NULL && script_cap > 0U) {
      (void)snprintf(script, script_cap, "%s", row);
    }
    return;
  }

  tab2 = strchr(tab1 + 1, '\t');
  if (tab2 == NULL) {
    cmaper_history_copy_text_range(script, script_cap, row,
                                   (size_t)(tab1 - row));
    if (target != NULL && target_cap > 0U) {
      (void)snprintf(target, target_cap, "%s", tab1 + 1);
    }
    return;
  }

  cmaper_history_copy_text_range(script, script_cap, row, (size_t)(tab1 - row));
  cmaper_history_copy_text_range(target, target_cap, tab1 + 1,
                                 (size_t)(tab2 - (tab1 + 1)));
  if (result != NULL && result_cap > 0U) {
    (void)snprintf(result, result_cap, "%s", tab2 + 1);
  }
}

static const char *cmaper_history_value_or_dash(const char *value) {
  if (value == NULL || value[0] == '\0') {
    return "-";
  }
  return value;
}

static const char *cmaper_history_session_color(bool use_ansi,
                                                const char *ansi_code) {
  if (!use_ansi) {
    return "";
  }
  return ansi_code;
}

static const char *cmaper_history_session_reset(bool use_ansi) {
  if (!use_ansi) {
    return "";
  }
  return "\033[0m";
}

static void cmaper_history_render_host_header_terminal(FILE *stream,
                                                       bool use_ansi,
                                                       const char *device_id,
                                                       size_t index,
                                                       size_t total) {
  const char *accent = cmaper_history_session_color(use_ansi, "\033[1;36m");
  const char *title = cmaper_history_session_color(use_ansi, "\033[1;35m");
  const char *reset = cmaper_history_session_reset(use_ansi);

  if (stream == NULL) {
    return;
  }

  fprintf(stream,
          "  "
          "%s=================================================================="
          "=====%s\n"
          "  %s[>] Device %s%s (%zu/%zu)\n",
          accent, reset, title, cmaper_history_value_or_dash(device_id), reset,
          index, total);
}

static void cmaper_history_render_host_kv_terminal(FILE *stream, bool use_ansi,
                                                   const char *label,
                                                   const char *value) {
  const char *label_color =
      cmaper_history_session_color(use_ansi, "\033[1;34m");
  const char *value_color =
      cmaper_history_session_color(use_ansi, "\033[0;37m");
  const char *reset = cmaper_history_session_reset(use_ansi);

  if (stream == NULL || label == NULL) {
    return;
  }

  fprintf(stream, "    %s[+] %-18s%s %s%s%s\n", label_color, label, reset,
          value_color, cmaper_history_value_or_dash(value), reset);
}

static void cmaper_history_render_detail_list_terminal(FILE *stream,
                                                       bool use_ansi,
                                                       const char *title,
                                                       const char *value) {
  const char *cursor;
  size_t emitted = 0U;
  const char *title_color =
      cmaper_history_session_color(use_ansi, "\033[1;33m");
  const char *item_color = cmaper_history_session_color(use_ansi, "\033[0;37m");
  const char *reset = cmaper_history_session_reset(use_ansi);

  if (stream == NULL || title == NULL) {
    return;
  }

  if (value == NULL || value[0] == '\0' || strcmp(value, "none") == 0) {
    fprintf(stream, "    %s[-] %s%s: none\n", title_color, title, reset);
    return;
  }

  fprintf(stream, "    %s[+] %s%s:\n", title_color, title, reset);

  cursor = value;
  while (cursor[0] != '\0') {
    const char *start = cursor;
    const char *end = NULL;
    size_t len;
    char token[CMAPER_HISTORY_DETAIL_CAP];

    while (start[0] == ' ' || start[0] == ',') {
      start += 1;
    }
    if (start[0] == '\0') {
      break;
    }

    end = strchr(start, ',');
    len = end != NULL ? (size_t)(end - start) : strlen(start);
    while (len > 0U && start[len - 1U] == ' ') {
      len -= 1U;
    }
    if (len > 0U) {
      cmaper_history_copy_text_range(token, sizeof(token), start, len);
      fprintf(stream, "      %s- %s%s\n", item_color, token, reset);
      emitted += 1U;
    }

    if (end == NULL) {
      break;
    }
    cursor = end + 1;
  }

  if (emitted == 0U) {
    fprintf(stream, "      %s- none%s\n", item_color, reset);
  }
}

static void cmaper_history_markdown_escape_cell(char *out, size_t out_cap,
                                                const char *value) {
  size_t src = 0U;
  size_t dst = 0U;

  if (out == NULL || out_cap == 0U) {
    return;
  }
  out[0] = '\0';

  if (value == NULL) {
    return;
  }

  while (value[src] != '\0' && dst + 1U < out_cap) {
    char ch = value[src++];
    if (ch == '\n' || ch == '\r' || ch == '\t') {
      ch = ' ';
    }
    if (ch == '|') {
      if (dst + 2U >= out_cap) {
        break;
      }
      out[dst++] = '\\';
      out[dst++] = '|';
      continue;
    }
    out[dst++] = ch;
  }
  out[dst] = '\0';
}

static void cmaper_history_render_script_results_markdown(
    FILE *stream, const cmaper_history_session_host_row_t *host) {
  const char *cursor;
  char line[CMAPER_HISTORY_DETAIL_CAP];

  if (stream == NULL || host == NULL) {
    return;
  }

  fprintf(stream, "  - Scripts used / Results (%zu entries):\n\n",
          host->script_result_count);
  fputs("    | Script | Target | Result |\n", stream);
  fputs("    |---|---|---|\n", stream);

  cursor = host->script_results;
  while (cmaper_history_script_row_next(&cursor, line, sizeof(line))) {
    char script[CMAPER_HISTORY_KEY_CAP];
    char target[CMAPER_HISTORY_TEXT_CAP];
    char result[CMAPER_HISTORY_DETAIL_CAP];
    char script_md[CMAPER_HISTORY_KEY_CAP * 2U];
    char target_md[CMAPER_HISTORY_TEXT_CAP * 2U];
    char result_md[CMAPER_HISTORY_DETAIL_CAP * 2U];

    cmaper_history_script_row_decode(line, script, sizeof(script), target,
                                     sizeof(target), result, sizeof(result));
    cmaper_history_markdown_escape_cell(script_md, sizeof(script_md), script);
    cmaper_history_markdown_escape_cell(target_md, sizeof(target_md), target);
    cmaper_history_markdown_escape_cell(result_md, sizeof(result_md), result);
    fprintf(stream, "    | `%s` | `%s` | %s |\n", script_md, target_md,
            result_md);
  }
}

static void cmaper_history_render_script_results_terminal(
    FILE *stream, bool use_ansi,
    const cmaper_history_session_host_row_t *host) {
  const char *cursor;
  char line[CMAPER_HISTORY_DETAIL_CAP];
  const char *title_color =
      cmaper_history_session_color(use_ansi, "\033[1;33m");
  const char *item_color = cmaper_history_session_color(use_ansi, "\033[0;37m");
  const char *reset = cmaper_history_session_reset(use_ansi);

  if (stream == NULL || host == NULL) {
    return;
  }

  fprintf(stream, "    %s[+] Scripts used / results%s (%zu):\n", title_color,
          reset, host->script_result_count);

  cursor = host->script_results;
  while (cmaper_history_script_row_next(&cursor, line, sizeof(line))) {
    char script[CMAPER_HISTORY_KEY_CAP];
    char target[CMAPER_HISTORY_TEXT_CAP];
    char result[CMAPER_HISTORY_DETAIL_CAP];

    cmaper_history_script_row_decode(line, script, sizeof(script), target,
                                     sizeof(target), result, sizeof(result));
    fprintf(stream,
            "      %s- %s [%s]%s\n"
            "        %s%s%s\n",
            item_color, cmaper_history_value_or_dash(script),
            cmaper_history_value_or_dash(target), reset, item_color,
            cmaper_history_value_or_dash(result), reset);
  }
}

void cmaper_history_render_sessions(
    FILE *stream, const cmaper_history_render_options_t *options,
    const cmaper_history_sessions_report_t *report) {
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
    fprintf(stream,
            "\"view\":\"%s\",\"db_available\":%s,\"limit\":%d,\"total_"
            "sessions\":%zu,\"shown\":%zu,\"truncated\":%s,",
            cmaper_output_view_name(view),
            report->db_available ? "true" : "false", report->limit,
            report->total_sessions, shown_count,
            report->truncated ? "true" : "false");
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
      fprintf(stream,
              ",\"host_count\":%zu,\"findings_open\":%zu,\"findings_high_or_"
              "worse\":%zu,\"management_surfaces\":%zu",
              row->host_count, row->findings_open, row->findings_high_or_worse,
              row->management_surfaces_total);
      fputc('}', stream);
    }
    fputs("]}\n", stream);
    return;
  }

  if (format == CMAPER_OUTPUT_FORMAT_MARKDOWN) {
    size_t max_open = 0U;
    size_t max_high = 0U;
    const char *latest_session = "-";

    fprintf(stream, "# Sessions\n\n## Context\n\n");
    fprintf(stream, "- Database: **%s**\n",
            report->db_available ? "ready" : "missing");
    fprintf(stream, "- Requested limit: **%d**\n", report->limit);
    fprintf(stream, "- Sessions available: **%zu**\n", report->total_sessions);
    fprintf(stream, "- Sessions shown: **%zu**\n", shown_count);

    if (!report->db_available) {
      fputs("\n## Notes\n\nNo history database found.\n", stream);
      return;
    }

    if (shown_count > 0U) {
      latest_session = report->items[0].session_id;
    }

    for (i = 0; i < shown_count; ++i) {
      const cmaper_history_session_row_t *row = &report->items[i];
      if (row->findings_open > max_open) {
        max_open = row->findings_open;
      }
      if (row->findings_high_or_worse > max_high) {
        max_high = row->findings_high_or_worse;
      }
    }

    fputs("\n## Key Takeaways\n\n", stream);
    fprintf(stream,
            "- **Risk:** **%s** (highest in shown sessions: open findings "
            "**%zu**, high/critical **%zu**)\n",
            max_high > 0U ? "CRITICAL" : (max_open > 0U ? "WARN" : "OK"),
            max_open, max_high);
    fprintf(stream, "- Most recent shown session: `%s`\n", latest_session);

    fputs("\n## Details\n\n| Session | Status | Started | Hosts | Open "
          "findings (high) | Surfaces |\n"
          "|---|---|---|---:|---:|---:|\n",
          stream);
    for (i = 0; i < shown_count; ++i) {
      const cmaper_history_session_row_t *row = &report->items[i];
      fprintf(stream, "| %s | %s | %s | %zu | %zu (%zu) | %zu |\n",
              row->session_id, row->status, row->started_at, row->host_count,
              row->findings_open, row->findings_high_or_worse,
              row->management_surfaces_total);
    }

    cmaper_history_render_truncated_note(stream, true, shown_count,
                                         report->count, "sessions");
    return;
  }

  cmaper_history_render_heading(stream, use_ansi, "Sessions");
  cmaper_history_render_section(stream, use_ansi, "Context");
  cmaper_history_render_key_value(stream, "Database",
                                  report->db_available ? "ready" : "missing");
  fprintf(stream, "  Requested limit: %d\n", report->limit);
  cmaper_history_render_key_size(stream, "Sessions available",
                                 report->total_sessions);
  cmaper_history_render_key_size(stream, "Sessions shown", shown_count);

  if (!report->db_available) {
    cmaper_history_render_section(stream, use_ansi, "Notes");
    fputs("  No history database found.\n", stream);
    return;
  }

  {
    size_t max_open = 0U;
    size_t max_high = 0U;
    const char *latest_session =
        shown_count > 0U ? report->items[0].session_id : "-";

    for (i = 0; i < shown_count; ++i) {
      const cmaper_history_session_row_t *row = &report->items[i];
      if (row->findings_open > max_open) {
        max_open = row->findings_open;
      }
      if (row->findings_high_or_worse > max_high) {
        max_high = row->findings_high_or_worse;
      }
    }

    cmaper_history_render_section(stream, use_ansi, "Key Takeaways");
    cmaper_history_render_risk(
        stream, use_ansi,
        cmaper_history_findings_risk_level(max_high, max_open),
        max_high > 0U
            ? "High/critical findings are present in shown sessions."
            : (max_open > 0U ? "Open findings are present in shown sessions."
                             : "No open findings in shown sessions."));
    fprintf(stream, "  Most recent shown session: %s\n", latest_session);

    cmaper_history_render_section(stream, use_ansi, "Details");
    if (shown_count == 0U) {
      fputs("  No sessions to display.\n", stream);
    }
    for (i = 0; i < shown_count; ++i) {
      const cmaper_history_session_row_t *row = &report->items[i];
      fprintf(stream,
              "  %s  status=%s  hosts=%zu  open findings=%zu (high=%zu)  "
              "surfaces=%zu\n",
              row->session_id, row->status, row->host_count, row->findings_open,
              row->findings_high_or_worse, row->management_surfaces_total);
      fprintf(stream, "    target=%s  started=%s\n", row->target,
              row->started_at);
    }
  }

  cmaper_history_render_truncated_note(stream, false, shown_count,
                                       report->count, "sessions");
}

void cmaper_history_render_session(
    FILE *stream, const cmaper_history_render_options_t *options,
    const cmaper_history_session_report_t *report) {
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
  shown_count =
      cmaper_history_render_count_for_view(report->host_count, view, 8U);

  if (format == CMAPER_OUTPUT_FORMAT_JSON) {
    fputs("{\"report\":\"session\",", stream);
    fprintf(stream, "\"view\":\"%s\",\"db_available\":%s,\"found\":%s,",
            cmaper_output_view_name(view),
            report->db_available ? "true" : "false",
            report->found ? "true" : "false");
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
    fprintf(stream,
            ",\"host_count\":%zu,\"findings_total\":%zu,\"findings_open\":%zu,"
            "\"findings_high_or_worse\":%zu,\"management_surfaces\":%zu",
            report->summary.host_count, report->summary.findings_total,
            report->summary.findings_open,
            report->summary.findings_high_or_worse,
            report->summary.management_surfaces_total);
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
      fprintf(stream,
              ",\"open_tcp_ports\":%zu,\"findings_open\":%zu,\"findings_high_"
              "or_worse\":%zu,\"management_surfaces\":%zu",
              host->open_tcp_ports, host->findings_open,
              host->findings_high_or_worse, host->management_surfaces);
      fputc('}', stream);
    }
    fputs("]}\n", stream);
    return;
  }

  if (format == CMAPER_OUTPUT_FORMAT_MARKDOWN) {
    if (!report->db_available) {
      fputs("# Session\n\n## Notes\n\nNo history database found.\n", stream);
      return;
    }
    if (!report->found) {
      fputs("# Session\n\n## Notes\n\nSession not found.\n", stream);
      return;
    }

    fprintf(stream, "# Session `%s`\n\n", report->summary.session_id);

    fputs("## Context\n\n", stream);
    fprintf(stream, "- Status: **%s**\n", report->summary.status);
    fprintf(stream, "- Target: `%s`\n", report->summary.target);
    fprintf(stream, "- Profile: `%s`\n", report->summary.profile);
    fprintf(stream, "- Started: `%s`\n", report->summary.started_at);
    fprintf(stream, "- Completed: `%s`\n", report->summary.completed_at);

    fputs("\n## Key Takeaways\n\n", stream);
    fprintf(
        stream,
        "- **Risk:** **%s** (open findings **%zu**, high/critical **%zu**)\n",
        report->summary.findings_high_or_worse > 0U
            ? "CRITICAL"
            : (report->summary.findings_open > 0U ? "WARN" : "OK"),
        report->summary.findings_open, report->summary.findings_high_or_worse);
    fprintf(stream, "- Hosts observed: **%zu**\n", report->summary.host_count);
    fprintf(stream, "- Management surfaces: **%zu**\n",
            report->summary.management_surfaces_total);
    if (strcmp(report->summary.profile, "low") == 0) {
      fputs("- Script pipeline: low profile keeps service detection/scripts "
            "disabled unless `--service-detection` is enabled.\n",
            stream);
    }

    fputs("\n## Details\n\n| Device | IP | Host status | Hostname | Open TCP | "
          "Open findings (high) | Surfaces |\n"
          "|---|---|---|---|---:|---:|---:|\n",
          stream);
    for (i = 0; i < shown_count; ++i) {
      const cmaper_history_session_host_row_t *host = &report->hosts[i];
      fprintf(stream, "| %s | %s | %s | %s | %zu | %zu (%zu) | %zu |\n",
              host->device_id, host->primary_ip, host->status, host->hostname,
              host->open_tcp_ports, host->findings_open,
              host->findings_high_or_worse, host->management_surfaces);
    }

    if (view == CMAPER_OUTPUT_VIEW_FULL && shown_count > 0U) {
      fputs("\n### Host Deep Details\n", stream);
      for (i = 0; i < shown_count; ++i) {
        const cmaper_history_session_host_row_t *host = &report->hosts[i];
        fprintf(stream, "\n- `%s` (`%s`)\n", host->device_id, host->primary_ip);
        fprintf(stream, "  - Open TCP ports: `%s`\n", host->open_tcp_list);
        if (host->script_result_count > 0U) {
          cmaper_history_render_script_results_markdown(stream, host);
        } else if (strcmp(report->summary.profile, "low") == 0) {
          fputs("  - Scripts used / Results: `none` (low profile default keeps "
                "service detection/scripts off)\n",
                stream);
        } else {
          fputs("  - Scripts used / Results: `none`\n", stream);
        }
        if (host->script_signal_count > 0U) {
          fprintf(stream, "  - Script-derived signals (%zu): `%s`\n",
                  host->script_signal_count, host->script_signals);
        } else if (strcmp(report->summary.profile, "low") == 0) {
          fputs("  - Script-derived signals: `none` (low profile default keeps "
                "service detection/scripts off)\n",
                stream);
        } else {
          fputs("  - Script-derived signals: `none`\n", stream);
        }
        fprintf(stream, "  - Findings detail: `%s`\n", host->findings_detail);
        fprintf(stream, "  - Management surfaces detail: `%s`\n",
                host->surfaces_detail);
      }
    }

    cmaper_history_render_truncated_note(stream, true, shown_count,
                                         report->host_count, "hosts");
    return;
  }

  if (!report->db_available) {
    cmaper_history_render_heading(stream, use_ansi, "Session");
    cmaper_history_render_section(stream, use_ansi, "Notes");
    fputs("  No history database found.\n", stream);
    return;
  }
  if (!report->found) {
    cmaper_history_render_heading(stream, use_ansi, "Session");
    cmaper_history_render_section(stream, use_ansi, "Notes");
    fputs("  Session not found.\n", stream);
    return;
  }

  cmaper_history_render_heading(stream, use_ansi, "Session");
  cmaper_history_render_section(stream, use_ansi, "Context");
  cmaper_history_render_key_value(stream, "Session",
                                  report->summary.session_id);
  cmaper_history_render_key_value(stream, "Status", report->summary.status);
  cmaper_history_render_key_value(stream, "Target", report->summary.target);
  cmaper_history_render_key_value(stream, "Profile", report->summary.profile);
  cmaper_history_render_key_value(stream, "Started",
                                  report->summary.started_at);
  cmaper_history_render_key_value(stream, "Completed",
                                  report->summary.completed_at);

  cmaper_history_render_section(stream, use_ansi, "Key Takeaways");
  cmaper_history_render_risk(
      stream, use_ansi,
      cmaper_history_findings_risk_level(report->summary.findings_high_or_worse,
                                         report->summary.findings_open),
      report->summary.findings_high_or_worse > 0U
          ? "This session still has high/critical findings."
          : (report->summary.findings_open > 0U
                 ? "This session still has open findings."
                 : "No open findings in this session."));
  cmaper_history_render_key_size(stream, "Hosts observed",
                                 report->summary.host_count);
  fprintf(stream, "  Open findings: %zu (high/critical: %zu)\n",
          report->summary.findings_open,
          report->summary.findings_high_or_worse);
  cmaper_history_render_key_size(stream, "Management surfaces",
                                 report->summary.management_surfaces_total);
  if (strcmp(report->summary.profile, "low") == 0) {
    cmaper_history_render_key_value(
        stream, "Script pipeline",
        "low profile default keeps service detection/scripts disabled (enable "
        "with --service-detection)");
  }

  cmaper_history_render_section(stream, use_ansi, "Details");
  if (shown_count == 0U) {
    fputs("  No hosts to display.\n", stream);
  }
  for (i = 0; i < shown_count; ++i) {
    const cmaper_history_session_host_row_t *host = &report->hosts[i];
    char summary[CMAPER_HISTORY_DETAIL_CAP];

    cmaper_history_render_host_header_terminal(
        stream, use_ansi, host->device_id, i + 1U, shown_count);
    cmaper_history_render_host_kv_terminal(stream, use_ansi, "IP",
                                           host->primary_ip);
    cmaper_history_render_host_kv_terminal(stream, use_ansi, "Host status",
                                           host->status);
    cmaper_history_render_host_kv_terminal(stream, use_ansi, "Hostname",
                                           host->hostname);
    snprintf(summary, sizeof(summary),
             "open_tcp=%zu | findings=%zu (high=%zu) | surfaces=%zu",
             host->open_tcp_ports, host->findings_open,
             host->findings_high_or_worse, host->management_surfaces);
    cmaper_history_render_host_kv_terminal(stream, use_ansi, "Summary",
                                           summary);
    if (view == CMAPER_OUTPUT_VIEW_FULL) {
      cmaper_history_render_detail_list_terminal(
          stream, use_ansi, "Open TCP ports", host->open_tcp_list);
      if (host->script_result_count > 0U) {
        cmaper_history_render_script_results_terminal(stream, use_ansi, host);
      } else if (strcmp(report->summary.profile, "low") == 0) {
        fputs("    Scripts used / results: none (low profile default keeps "
              "service detection/scripts off)\n",
              stream);
      } else {
        fputs("    Scripts used / results: none\n", stream);
      }
      if (host->script_signal_count > 0U && host->script_signals[0] != '\0') {
        cmaper_history_render_detail_list_terminal(
            stream, use_ansi, "Script-derived signals", host->script_signals);
      } else if (strcmp(report->summary.profile, "low") == 0) {
        fputs("    Script-derived signals: none (low profile default keeps "
              "service detection/scripts off)\n",
              stream);
      } else {
        fputs("    Script-derived signals: none\n", stream);
      }
      cmaper_history_render_detail_list_terminal(
          stream, use_ansi, "Findings detail", host->findings_detail);
      cmaper_history_render_detail_list_terminal(stream, use_ansi,
                                                 "Management surfaces detail",
                                                 host->surfaces_detail);
      fputc('\n', stream);
    }
  }

  cmaper_history_render_truncated_note(stream, false, shown_count,
                                       report->host_count, "hosts");
}
