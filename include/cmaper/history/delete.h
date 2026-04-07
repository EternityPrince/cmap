#ifndef CMAPER_HISTORY_DELETE_H
#define CMAPER_HISTORY_DELETE_H

#include <stdbool.h>

#include "cmaper/core/error.h"
#include "cmaper/history/domain.h"

typedef struct {
  bool db_available;
  bool session_found;
  bool performed;
  char session_id[CMAPER_HISTORY_ID_CAP];
  size_t sessions_before;
  size_t sessions_deleted;
  size_t orphan_devices_deleted;
  size_t orphan_networks_deleted;
} cmaper_history_delete_report_t;

void cmaper_history_delete_report_init(cmaper_history_delete_report_t *report);

cmaper_err_t
cmaper_history_delete_session(const char *db_path, const char *session_token,
                              cmaper_history_delete_report_t *report);

cmaper_err_t
cmaper_history_delete_all_sessions(const char *db_path,
                                   cmaper_history_delete_report_t *report);

#endif
