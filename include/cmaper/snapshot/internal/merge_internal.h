#ifndef CMAPER_SNAPSHOT_MERGE_INTERNAL_H
#define CMAPER_SNAPSHOT_MERGE_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>

#include "cmaper/core/error.h"
#include "cmaper/core/log.h"
#include "cmaper/scan/artifact.h"
#include "cmaper/scan/nmap_xml_model.h"
#include "cmaper/scan/runner.h"

#define CMAPER_SNAPSHOT_IP_CAP 64

typedef struct {
    char ip[CMAPER_SNAPSHOT_IP_CAP];
    char xml_path[CMAPER_SCAN_ARTIFACT_PATH_CAP];
    cmaper_nmap_xml_document_t document;
    const cmaper_nmap_xml_host_t *host;
    bool loaded;
} cmaper_snapshot_detail_doc_t;

typedef struct {
    char ip[CMAPER_SNAPSHOT_IP_CAP];
    const cmaper_nmap_xml_host_t *discovery_host;
    const cmaper_snapshot_detail_doc_t *detail_doc;
} cmaper_snapshot_merged_host_t;

void cmaper_snapshot_detail_docs_dispose(
    cmaper_snapshot_detail_doc_t *items,
    size_t count
);

void cmaper_snapshot_merged_hosts_dispose(cmaper_snapshot_merged_host_t *items);

cmaper_err_t cmaper_snapshot_build_detail_docs(
    const cmaper_scan_result_t *scan_result,
    cmaper_snapshot_detail_doc_t **out_items,
    size_t *out_count,
    cmaper_logger_t *logger
);

cmaper_err_t cmaper_snapshot_build_merged_hosts(
    const cmaper_nmap_xml_document_t *discovery_doc,
    const cmaper_snapshot_detail_doc_t *detail_docs,
    size_t detail_doc_count,
    cmaper_snapshot_merged_host_t **out_items,
    size_t *out_count
);

#endif
