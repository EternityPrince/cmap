#ifndef CMAPER_HISTORY_ALERTS_H
#define CMAPER_HISTORY_ALERTS_H

#include "cmaper/core/error.h"
#include "cmaper/history/diff.h"
#include "cmaper/history/domain.h"

cmaper_err_t
cmaper_history_alerts_build_for_diff(cmaper_history_diff_report_t *report);
cmaper_err_t cmaper_history_alerts_build_for_posture(
    cmaper_history_posture_report_t *report);

#endif
