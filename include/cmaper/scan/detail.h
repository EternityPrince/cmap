#ifndef CMAPER_SCAN_DETAIL_H
#define CMAPER_SCAN_DETAIL_H

#include <stdbool.h>
#include <stddef.h>

#include "cmaper/core/error.h"
#include "cmaper/core/log.h"
#include "cmaper/runtime/paths.h"
#include "cmaper/scan/artifact.h"
#include "cmaper/scan/detail_targets.h"
#include "cmaper/scan/plan.h"
#include "cmaper/scan/process.h"
#include "cmaper/scan/source_identity.h"

#define CMAPER_SCAN_DETAIL_HOST_MSG_CAP 256

typedef struct {
    char ip[CMAPER_SCAN_DETAIL_TARGET_IP_CAP];
    bool success;
    bool direct_scan_attempted;
    bool direct_scan_success;
    bool probe_attempted;
    bool probe_success;
    bool enrichment_attempted;
    bool enrichment_success;
    bool used_probe_xml_as_final;
    bool xml_saved;
    char xml_path[CMAPER_SCAN_ARTIFACT_PATH_CAP];
    char message[CMAPER_SCAN_DETAIL_HOST_MSG_CAP];
} cmaper_scan_detail_host_result_t;

typedef struct {
    cmaper_scan_detail_host_result_t *hosts;
    size_t host_count;
    size_t successful_hosts;
    size_t failed_hosts;
    size_t degraded_hosts;
} cmaper_scan_detail_result_t;

typedef struct {
    const cmaper_scan_plan_t *plan;
    const cmaper_scan_source_identity_t *source_identity;
    const cmaper_runtime_paths_t *paths;
    const cmaper_scan_detail_target_list_t *targets;
    const cmaper_scan_artifact_policy_t *artifact_policy;
    int worker_limit;
    cmaper_scan_process_run_fn process_backend;
    cmaper_logger_t *logger;
} cmaper_scan_detail_request_t;

void cmaper_scan_detail_result_init(cmaper_scan_detail_result_t *result);
void cmaper_scan_detail_result_dispose(cmaper_scan_detail_result_t *result);

cmaper_err_t cmaper_scan_detail_execute(
    const cmaper_scan_detail_request_t *request,
    cmaper_scan_detail_result_t *result
);

#endif
