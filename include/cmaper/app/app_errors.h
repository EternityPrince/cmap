#ifndef CMAPER_APP_APP_ERRORS_H
#define CMAPER_APP_APP_ERRORS_H

#include "cmaper/cli/diagnostic.h"
#include "cmaper/runtime/paths.h"
#include "cmaper/scan/plan.h"
#include "cmaper/snapshot/store.h"

int cmaper_app_usage_error(const char *program_name,
                                  const cmaper_cli_diagnostic_t *diag);
int cmaper_app_scan_plan_error(const char *program_name,
                                      const cmaper_scan_plan_diag_t *diag);
int cmaper_app_runtime_error(const char *program_name,
                                    const cmaper_runtime_paths_diag_t *diag);
int cmaper_app_snapshot_error(const char *program_name,
                                     const cmaper_snapshot_diag_t *diag);
void cmaper_app_make_session_uid(char *out, size_t out_cap);

#endif // !CMAPER_APP_ERRORS_H
