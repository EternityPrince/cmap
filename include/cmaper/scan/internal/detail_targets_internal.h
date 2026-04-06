#ifndef CMAPER_SCAN_INTERNAL_DETAIL_TARGETS_INTERNAL_H
#define CMAPER_SCAN_INTERNAL_DETAIL_TARGETS_INTERNAL_H

#include "cmaper/scan/detail_targets.h"

void cmaper_scan_detail_target_diag_setf(
    cmaper_scan_detail_target_diag_t *diag,
    const char *field,
    const char *fmt,
    ...
);

void cmaper_scan_detail_target_dispose(cmaper_scan_detail_target_t *target);

int cmaper_scan_detail_target_compare(const void *left, const void *right);

cmaper_err_t cmaper_scan_detail_targets_deduplicate(cmaper_scan_detail_target_list_t *targets);

#endif
