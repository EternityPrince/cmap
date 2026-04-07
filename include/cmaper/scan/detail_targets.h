#ifndef CMAPER_SCAN_DETAIL_TARGETS_H
#define CMAPER_SCAN_DETAIL_TARGETS_H

#include <stdbool.h>
#include <stddef.h>

#include "cmaper/core/error.h"
#include "cmaper/scan/nmap_xml_model.h"

#define CMAPER_SCAN_DETAIL_TARGET_IP_CAP 64
#define CMAPER_SCAN_DETAIL_TARGET_DIAG_CAP 256

typedef struct {
  char ip[CMAPER_SCAN_DETAIL_TARGET_IP_CAP];
  int *open_tcp_ports;
  size_t open_tcp_port_count;
  bool has_open_tcp_ports;
} cmaper_scan_detail_target_t;

typedef struct {
  cmaper_scan_detail_target_t *items;
  size_t count;
} cmaper_scan_detail_target_list_t;

typedef struct {
  const char *field;
  char message[CMAPER_SCAN_DETAIL_TARGET_DIAG_CAP];
} cmaper_scan_detail_target_diag_t;

void cmaper_scan_detail_target_diag_clear(
    cmaper_scan_detail_target_diag_t *diag);
void cmaper_scan_detail_targets_init(cmaper_scan_detail_target_list_t *list);
void cmaper_scan_detail_targets_dispose(cmaper_scan_detail_target_list_t *list);

cmaper_err_t cmaper_scan_detail_targets_build(
    const cmaper_nmap_xml_document_t *discovery_document,
    cmaper_scan_detail_target_list_t *targets,
    cmaper_scan_detail_target_diag_t *diag);

#endif
