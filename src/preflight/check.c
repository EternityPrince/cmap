#include "cmaper/preflight/check.h"

#include <stdio.h>

#include "cmaper/platform/fs.h"

static const char *cmaper_preflight_ok(bool value) {
  return value ? "ok" : "fail";
}

static const char *cmaper_preflight_status_word(bool value) {
  return value ? "OK" : "FAIL";
}

void cmaper_preflight_report_init(cmaper_preflight_report_t *report) {
  if (report == NULL) {
    return;
  }

  report->nmap_found = false;
  report->db_dir_ready = false;
  report->xml_output_dir_ready = false;
  report->scripts_dir_ready = false;
  report->helper_selftest_ok = false;
  report->stdout_available = false;
  report->stderr_available = false;
  report->stdout_stderr_separated = false;
  report->success = false;
}

cmaper_err_t cmaper_preflight_run(const cmaper_runtime_paths_t *paths,
                                  cmaper_logger_t *logger,
                                  cmaper_preflight_report_t *report) {
  cmaper_err_t rc;
  int stdout_fd;
  int stderr_fd;

  if (paths == NULL || report == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  cmaper_preflight_report_init(report);

  cmaper_log(logger, CMAPER_LOG_PHASE, "preflight: starting");

  cmaper_log(logger, CMAPER_LOG_WAIT, "preflight: checking nmap binary");
  report->nmap_found = paths->nmap_bin[0] != '\0' &&
                       cmaper_fs_path_is_executable(paths->nmap_bin);
  if (report->nmap_found) {
    cmaper_log(logger, CMAPER_LOG_OK, "preflight: nmap found at '%s'",
               paths->nmap_bin);
  } else {
    cmaper_log(logger, CMAPER_LOG_FAIL,
               "preflight: nmap binary was not resolved");
  }

  cmaper_log(logger, CMAPER_LOG_WAIT,
             "preflight: ensuring runtime directories");
  rc = cmaper_fs_ensure_directory_recursive(paths->db_dir);
  report->db_dir_ready =
      (rc == CMAPER_OK) && cmaper_fs_path_is_directory(paths->db_dir);

  rc = cmaper_fs_ensure_directory_recursive(paths->xml_output_dir);
  report->xml_output_dir_ready =
      (rc == CMAPER_OK) && cmaper_fs_path_is_directory(paths->xml_output_dir);

  if (paths->has_nmap_scripts_dir) {
    report->scripts_dir_ready =
        cmaper_fs_path_is_directory(paths->nmap_scripts_dir);
  } else {
    report->scripts_dir_ready = false;
  }

  cmaper_log(logger, report->db_dir_ready ? CMAPER_LOG_OK : CMAPER_LOG_FAIL,
             "preflight: db-dir '%s' => %s", paths->db_dir,
             cmaper_preflight_ok(report->db_dir_ready));
  cmaper_log(logger,
             report->xml_output_dir_ready ? CMAPER_LOG_OK : CMAPER_LOG_FAIL,
             "preflight: xml-dir '%s' => %s", paths->xml_output_dir,
             cmaper_preflight_ok(report->xml_output_dir_ready));

  if (paths->has_nmap_scripts_dir) {
    cmaper_log(logger,
               report->scripts_dir_ready ? CMAPER_LOG_OK : CMAPER_LOG_WARN,
               "preflight: scripts-dir '%s' => %s", paths->nmap_scripts_dir,
               report->scripts_dir_ready ? "ok" : "missing");
  } else {
    cmaper_log(logger, CMAPER_LOG_WARN,
               "preflight: scripts-dir was not resolved");
  }

  cmaper_log(logger, CMAPER_LOG_WAIT,
             "preflight: checking helper/runtime sanity");
  report->helper_selftest_ok = paths->db_path[0] != '\0' &&
                               paths->db_dir[0] != '\0' &&
                               paths->xml_output_dir[0] != '\0';
  cmaper_log(logger,
             report->helper_selftest_ok ? CMAPER_LOG_OK : CMAPER_LOG_FAIL,
             "preflight: helper-runtime-sanity => %s",
             cmaper_preflight_ok(report->helper_selftest_ok));

  cmaper_log(logger, CMAPER_LOG_WAIT,
             "preflight: checking stdout/stderr separation");
  stdout_fd = fileno(stdout);
  stderr_fd = fileno(stderr);
  report->stdout_available = stdout_fd >= 0;
  report->stderr_available = stderr_fd >= 0;
  report->stdout_stderr_separated = report->stdout_available &&
                                    report->stderr_available &&
                                    stdout_fd != stderr_fd;

  cmaper_log(logger,
             report->stdout_stderr_separated ? CMAPER_LOG_OK : CMAPER_LOG_FAIL,
             "preflight: stdout/stderr separation => %s",
             cmaper_preflight_ok(report->stdout_stderr_separated));

  report->success = report->nmap_found && report->db_dir_ready &&
                    report->xml_output_dir_ready && report->scripts_dir_ready &&
                    report->helper_selftest_ok && report->stdout_available &&
                    report->stderr_available && report->stdout_stderr_separated;

  cmaper_log(logger, report->success ? CMAPER_LOG_OK : CMAPER_LOG_FAIL,
             "preflight: finished => %s",
             report->success ? "success" : "failure");

  return report->success ? CMAPER_OK : CMAPER_ERR_INTERNAL;
}

void cmaper_preflight_render_report(FILE *stream,
                                    const cmaper_preflight_report_t *report,
                                    const cmaper_runtime_paths_t *paths) {
  const char *nmap_bin = "(not found)";
  const char *scripts_dir = "(not resolved)";

  if (stream == NULL || report == NULL || paths == NULL) {
    return;
  }

  if (paths->nmap_bin[0] != '\0') {
    nmap_bin = paths->nmap_bin;
  }

  if (paths->has_nmap_scripts_dir && paths->nmap_scripts_dir[0] != '\0') {
    scripts_dir = paths->nmap_scripts_dir;
  }

  fprintf(stream,
          "Preflight report\n"
          "  result: %s\n"
          "  nmap-bin: %s [%s]\n"
          "  scripts-dir: %s [%s]\n"
          "  db-path: %s\n"
          "  db-dir-ready: %s\n"
          "  xml-output-dir: %s\n"
          "  xml-dir-ready: %s\n"
          "  helper-selftest: %s\n"
          "  stdout-available: %s\n"
          "  stderr-available: %s\n"
          "  stdout/stderr-separated: %s\n",
          cmaper_preflight_status_word(report->success), nmap_bin,
          cmaper_preflight_status_word(report->nmap_found), scripts_dir,
          cmaper_preflight_status_word(report->scripts_dir_ready),
          paths->db_path, cmaper_preflight_status_word(report->db_dir_ready),
          paths->xml_output_dir,
          cmaper_preflight_status_word(report->xml_output_dir_ready),
          cmaper_preflight_status_word(report->helper_selftest_ok),
          cmaper_preflight_status_word(report->stdout_available),
          cmaper_preflight_status_word(report->stderr_available),
          cmaper_preflight_status_word(report->stdout_stderr_separated));
}
