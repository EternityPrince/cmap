#include "cmaper/history/internal/service_internal.h"

#include <stdio.h>
#include <string.h>

#include "cmaper/platform/terminal.h"

static bool cmaper_history_is_confirmed_yes(const char *line) {
  size_t i = 0;

  if (line == NULL) {
    return false;
  }

  while (line[i] == ' ' || line[i] == '\t' || line[i] == '\r' ||
         line[i] == '\n') {
    i += 1U;
  }

  if (line[i] != 'y') {
    return false;
  }
  i += 1U;

  while (line[i] == ' ' || line[i] == '\t' || line[i] == '\r' ||
         line[i] == '\n') {
    i += 1U;
  }

  return line[i] == '\0';
}

static cmaper_err_t cmaper_history_prompt_delete(const char *prompt_label,
                                                 bool *out_confirmed) {
  char answer[32];

  if (out_confirmed == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_confirmed = false;

  if (!cmaper_terminal_is_tty(stdin) || !cmaper_terminal_is_tty(stderr)) {
    return CMAPER_ERR_CLI_USAGE;
  }

  fprintf(stderr, "%s Type 'y' to confirm: ", prompt_label);
  fflush(stderr);

  if (fgets(answer, sizeof(answer), stdin) == NULL) {
    return CMAPER_OK;
  }

  *out_confirmed = cmaper_history_is_confirmed_yes(answer);
  return CMAPER_OK;
}

static void cmaper_history_json_escape(FILE *stream, const char *value) {
  size_t i;

  if (stream == NULL || value == NULL) {
    return;
  }

  for (i = 0; value[i] != '\0'; ++i) {
    unsigned char ch = (unsigned char)value[i];
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
        fprintf(stream, "\\u%04x", (unsigned int)ch);
      } else {
        fputc((int)ch, stream);
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

static void cmaper_history_render_delete_report(
    FILE *stream, const cmaper_output_options_t *output,
    const cmaper_history_delete_report_t *report, bool confirmed,
    bool delete_all) {
  cmaper_output_format_t format;

  if (stream == NULL || output == NULL || report == NULL) {
    return;
  }

  format = output->format;

  if (format == CMAPER_OUTPUT_FORMAT_JSON) {
    fputs("{\"report\":", stream);
    if (delete_all) {
      fputs("\"delete-all-sessions\",", stream);
    } else {
      fputs("\"delete-session\",", stream);
    }
    fprintf(stream, "\"confirmed\":%s,\"db_available\":%s,\"performed\":%s,",
            confirmed ? "true" : "false",
            report->db_available ? "true" : "false",
            report->performed ? "true" : "false");
    if (!delete_all) {
      fputs("\"session_id\":", stream);
      cmaper_history_json_string(stream, report->session_id);
      fprintf(stream, ",\"session_found\":%s,",
              report->session_found ? "true" : "false");
    }
    fprintf(stream,
            "\"sessions_before\":%zu,\"sessions_deleted\":%zu,\"orphan_devices_"
            "deleted\":%zu,\"orphan_networks_deleted\":%zu}\n",
            report->sessions_before, report->sessions_deleted,
            report->orphan_devices_deleted, report->orphan_networks_deleted);
    return;
  }

  if (format == CMAPER_OUTPUT_FORMAT_MARKDOWN) {
    fprintf(stream,
            "# %s\n\n- Confirmed: **%s**\n- Database available: **%s**\n- "
            "Performed: **%s**\n- Sessions before: **%zu**\n- Sessions "
            "deleted: **%zu**\n- Orphan devices deleted: **%zu**\n- Orphan "
            "networks deleted: **%zu**\n",
            delete_all ? "Delete all sessions" : "Delete session",
            confirmed ? "yes" : "no", report->db_available ? "yes" : "no",
            report->performed ? "yes" : "no", report->sessions_before,
            report->sessions_deleted, report->orphan_devices_deleted,
            report->orphan_networks_deleted);
    if (!delete_all) {
      fprintf(stream, "- Session id: `%s`\n- Session found: **%s**\n",
              report->session_id[0] != '\0' ? report->session_id : "(unknown)",
              report->session_found ? "yes" : "no");
    }
    return;
  }

  fprintf(stream,
          "%s\n  confirmed=%s db=%s performed=%s sessions-before=%zu "
          "deleted=%zu orphan-devices=%zu orphan-networks=%zu\n",
          delete_all ? "Delete-all sessions" : "Delete session",
          confirmed ? "yes" : "no", report->db_available ? "ready" : "missing",
          report->performed ? "yes" : "no", report->sessions_before,
          report->sessions_deleted, report->orphan_devices_deleted,
          report->orphan_networks_deleted);
  if (!delete_all) {
    fprintf(stream, "  session=%s found=%s\n",
            report->session_id[0] != '\0' ? report->session_id : "(unknown)",
            report->session_found ? "yes" : "no");
  }
}

cmaper_err_t
cmaper_history_run_delete_session(const cmaper_cli_config_t *config,
                                  const cmaper_runtime_paths_t *paths,
                                  FILE *report_stream) {
  cmaper_history_delete_report_t report;
  bool confirmed = false;
  cmaper_err_t rc;

  if (config == NULL || paths == NULL || report_stream == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  cmaper_history_delete_report_init(&report);
  if (config->history.session_id != NULL) {
    cmaper_history_copy_string(report.session_id, sizeof(report.session_id),
                               config->history.session_id);
  }

  rc = cmaper_history_prompt_delete("Delete session is destructive.",
                                    &confirmed);
  if (rc != CMAPER_OK) {
    if (rc == CMAPER_ERR_CLI_USAGE) {
      fprintf(stderr,
              "delete-session requires an interactive TTY for confirmation\n");
    }
    return rc;
  }

  if (confirmed) {
    rc = cmaper_history_delete_session(paths->db_path,
                                       config->history.session_id, &report);
    if (rc != CMAPER_OK) {
      return rc;
    }
  }

  cmaper_history_render_delete_report(report_stream, &config->output, &report,
                                      confirmed, false);
  return CMAPER_OK;
}

cmaper_err_t cmaper_history_run_delete_all(const cmaper_cli_config_t *config,
                                           const cmaper_runtime_paths_t *paths,
                                           FILE *report_stream) {
  cmaper_history_delete_report_t report;
  bool confirmed = false;
  cmaper_err_t rc;

  if (config == NULL || paths == NULL || report_stream == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  cmaper_history_delete_report_init(&report);

  rc = cmaper_history_prompt_delete("Delete all sessions is destructive.",
                                    &confirmed);
  if (rc != CMAPER_OK) {
    if (rc == CMAPER_ERR_CLI_USAGE) {
      fprintf(
          stderr,
          "delete-all-sessions requires an interactive TTY for confirmation\n");
    }
    return rc;
  }

  if (confirmed) {
    rc = cmaper_history_delete_all_sessions(paths->db_path, &report);
    if (rc != CMAPER_OK) {
      return rc;
    }
  }

  cmaper_history_render_delete_report(report_stream, &config->output, &report,
                                      confirmed, true);
  return CMAPER_OK;
}
