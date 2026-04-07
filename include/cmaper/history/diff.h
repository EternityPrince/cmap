#ifndef CMAPER_HISTORY_DIFF_H
#define CMAPER_HISTORY_DIFF_H

#include <stdbool.h>
#include <stddef.h>

#include "cmaper/core/error.h"
#include "cmaper/history/domain.h"
#include "cmaper/history/query.h"

const char *
cmaper_history_host_reason_name(cmaper_history_host_reason_t reason);
bool cmaper_history_host_reason_has(unsigned int mask,
                                    cmaper_history_host_reason_t reason);

cmaper_err_t cmaper_history_diff_build(
    const cmaper_history_host_snapshot_t *from_hosts, size_t from_host_count,
    const cmaper_history_host_snapshot_t *to_hosts, size_t to_host_count,
    cmaper_history_diff_report_t *out_report);

#endif
