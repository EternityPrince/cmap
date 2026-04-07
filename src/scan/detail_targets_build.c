#include "cmaper/scan/detail_targets.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmaper/scan/internal/detail_targets_internal.h"
#include "cmaper/scan/nmap_xml_utils.h"

static cmaper_err_t
cmaper_scan_detail_target_list_append(cmaper_scan_detail_target_list_t *targets,
                                      cmaper_scan_detail_target_t target) {
  cmaper_scan_detail_target_t *next;

  next = (cmaper_scan_detail_target_t *)realloc(
      targets->items,
      (targets->count + 1U) * sizeof(cmaper_scan_detail_target_t));
  if (next == NULL) {
    return CMAPER_ERR_OOM;
  }

  targets->items = next;
  targets->items[targets->count] = target;
  targets->count += 1U;
  return CMAPER_OK;
}

cmaper_err_t cmaper_scan_detail_targets_build(
    const cmaper_nmap_xml_document_t *discovery_document,
    cmaper_scan_detail_target_list_t *targets,
    cmaper_scan_detail_target_diag_t *diag) {
  size_t i;
  cmaper_err_t rc;

  if (discovery_document == NULL || targets == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  cmaper_scan_detail_target_diag_clear(diag);
  cmaper_scan_detail_targets_dispose(targets);
  cmaper_scan_detail_targets_init(targets);

  for (i = 0; i < discovery_document->host_count; ++i) {
    const cmaper_nmap_xml_host_t *host = &discovery_document->hosts[i];
    const char *ip;
    cmaper_scan_detail_target_t target;

    if (host->status.state == NULL || strcmp(host->status.state, "up") != 0) {
      continue;
    }

    ip = cmaper_nmap_host_primary_ip(host);
    if (ip == NULL || ip[0] == '\0') {
      continue;
    }

    memset(&target, 0, sizeof(target));
    if (snprintf(target.ip, sizeof(target.ip), "%s", ip) >=
        (int)sizeof(target.ip)) {
      cmaper_scan_detail_target_diag_setf(
          diag, "ip", "host primary ip exceeds internal limit: '%s'", ip);
      cmaper_scan_detail_target_dispose(&target);
      cmaper_scan_detail_targets_dispose(targets);
      return CMAPER_ERR_PARSE;
    }

    rc = cmaper_nmap_host_open_tcp_ports_sorted(host, &target.open_tcp_ports,
                                                &target.open_tcp_port_count);
    if (rc != CMAPER_OK) {
      cmaper_scan_detail_target_diag_setf(
          diag, "ports", "failed to extract open tcp ports for host '%s'",
          target.ip);
      cmaper_scan_detail_target_dispose(&target);
      cmaper_scan_detail_targets_dispose(targets);
      return rc;
    }
    target.has_open_tcp_ports = target.open_tcp_port_count > 0;

    rc = cmaper_scan_detail_target_list_append(targets, target);
    if (rc != CMAPER_OK) {
      cmaper_scan_detail_target_diag_setf(diag, "targets",
                                          "failed to append detail target");
      cmaper_scan_detail_target_dispose(&target);
      cmaper_scan_detail_targets_dispose(targets);
      return rc;
    }
  }

  if (targets->count > 1U) {
    qsort(targets->items, targets->count, sizeof(cmaper_scan_detail_target_t),
          cmaper_scan_detail_target_compare);

    rc = cmaper_scan_detail_targets_deduplicate(targets);
    if (rc != CMAPER_OK) {
      cmaper_scan_detail_target_diag_setf(
          diag, "targets", "failed to deduplicate detail targets");
      cmaper_scan_detail_targets_dispose(targets);
      return rc;
    }
  }

  return CMAPER_OK;
}
