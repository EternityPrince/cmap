#ifndef CMAPER_SCAN_SCRIPT_PIPELINE_H
#define CMAPER_SCAN_SCRIPT_PIPELINE_H

#include <stddef.h>

typedef enum {
    CMAPER_SCAN_SCRIPT_SET_NMAP_DEFAULT = 0,
    CMAPER_SCAN_SCRIPT_SET_WEB_BASELINE,
    CMAPER_SCAN_SCRIPT_SET_TLS_BASELINE,
    CMAPER_SCAN_SCRIPT_SET_DNS_BASELINE,
    CMAPER_SCAN_SCRIPT_SET_SMB_BASELINE
} cmaper_scan_script_set_t;

typedef struct {
    cmaper_scan_script_set_t id;
    const char *key;
    const char *description;
    const char *script_expression;
} cmaper_scan_script_set_info_t;

size_t cmaper_scan_script_set_list(const cmaper_scan_script_set_info_t **out_items);

const cmaper_scan_script_set_info_t *cmaper_scan_script_set_info(cmaper_scan_script_set_t id);

#endif
