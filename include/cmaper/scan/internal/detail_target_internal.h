#ifndef CMAPER_SCAN_INTERNAL_DETAIL_TARGET_INTERNAL_H
#define CMAPER_SCAN_INTERNAL_DETAIL_TARGET_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>

#include "cmaper/core/error.h"

cmaper_err_t cmaper_scan_detail_target_extract_probe_ports(
    const char *probe_xml_path, const char *target_ip, int **out_ports,
    size_t *out_port_count);

bool cmaper_scan_detail_target_count_scripts(const char *xml_path,
                                             const char *target_ip,
                                             size_t *out_scripts_count);

#endif
