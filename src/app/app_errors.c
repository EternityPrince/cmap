#include <unistd.h>
#include "cmaper/cli/diagnostic.h"
#include "cmaper/cli/help.h"
#include "cmaper/core/error.h"
#include "cmaper/runtime/paths.h"
#include "cmaper/scan/plan.h"
#include "cmaper/snapshot/store.h"
#include "cmaper/app/app_errors.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

int cmaper_app_usage_error(const char *program_name,
                                  const cmaper_cli_diagnostic_t *diag) {
  const char *message = "invalid command line arguments";

  if (diag != NULL && diag->message[0] != '\0') {
    message = diag->message;
  }

  if (diag != NULL && diag->argument != NULL) {
    fprintf(stderr, "%s: %s (%s)\n\n", program_name, message, diag->argument);
  } else {
    fprintf(stderr, "%s: %s\n\n", program_name, message);
  }

  cmaper_cli_print_help(stderr, program_name, NULL);
  return cmaper_err_to_exit_code(CMAPER_ERR_CLI_USAGE);
}

int cmaper_app_scan_plan_error(const char *program_name,
                                      const cmaper_scan_plan_diag_t *diag) {
  const char *message = "invalid scan plan";

  if (diag != NULL && diag->message[0] != '\0') {
    message = diag->message;
  }

  if (diag != NULL && diag->field != NULL) {
    fprintf(stderr, "%s: %s (%s)\n\n", program_name, message, diag->field);
  } else {
    fprintf(stderr, "%s: %s\n\n", program_name, message);
  }

  cmaper_cli_print_help(stderr, program_name, "scan");
  return cmaper_err_to_exit_code(CMAPER_ERR_CLI_USAGE);
}

int cmaper_app_runtime_error(const char *program_name,
                                    const cmaper_runtime_paths_diag_t *diag) {
  const char *message = "runtime initialization failed";

  if (diag != NULL && diag->message[0] != '\0') {
    message = diag->message;
  }

  if (diag != NULL && diag->field != NULL) {
    fprintf(stderr, "%s: %s (%s)\n", program_name, message, diag->field);
  } else {
    fprintf(stderr, "%s: %s\n", program_name, message);
  }

  return cmaper_err_to_exit_code(CMAPER_ERR_INTERNAL);
}

int cmaper_app_snapshot_error(const char *program_name,
                                     const cmaper_snapshot_diag_t *diag) {
  const char *message = "snapshot storage initialization failed";

  if (diag != NULL && diag->message[0] != '\0') {
    message = diag->message;
  }

  if (diag != NULL && diag->field != NULL) {
    fprintf(stderr, "%s: %s (%s)\n", program_name, message, diag->field);
  } else {
    fprintf(stderr, "%s: %s\n", program_name, message);
  }

  return cmaper_err_to_exit_code(CMAPER_ERR_INTERNAL);
}

void cmaper_app_make_session_uid(char *out, size_t out_cap) {
  time_t now;
  long pid;

  if (out == NULL || out_cap == 0) {
    return;
  }

  now = time(NULL);
  pid = (long)getpid();
  snprintf(out, out_cap, "session-%lld-%ld", (long long)now, pid);
}
