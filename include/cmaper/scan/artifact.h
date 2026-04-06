#ifndef CMAPER_SCAN_ARTIFACT_H
#define CMAPER_SCAN_ARTIFACT_H

#include <stdbool.h>
#include <stddef.h>

#include "cmaper/core/error.h"
#include "cmaper/runtime/paths.h"

#define CMAPER_SCAN_ARTIFACT_PATH_CAP 2048

typedef struct {
    bool save_discovery_xml;
    bool save_host_xml;
    const char *session_id;
} cmaper_scan_artifact_policy_t;

cmaper_err_t cmaper_scan_artifact_save_discovery_xml(
    const cmaper_runtime_paths_t *paths,
    const cmaper_scan_artifact_policy_t *policy,
    const char *xml_data,
    size_t xml_size,
    char *out_path,
    size_t out_path_cap
);

cmaper_err_t cmaper_scan_artifact_save_host_xml(
    const cmaper_runtime_paths_t *paths,
    const cmaper_scan_artifact_policy_t *policy,
    const char *host_ip,
    const char *xml_data,
    size_t xml_size,
    char *out_path,
    size_t out_path_cap
);

#endif
