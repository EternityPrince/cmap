#ifndef CMAPER_SNAPSHOT_HOST_VIEW_INTERNAL_H
#define CMAPER_SNAPSHOT_HOST_VIEW_INTERNAL_H

#include <stddef.h>

#include "cmaper/core/error.h"
#include "cmaper/scan/nmap_xml_model.h"
#include "cmaper/snapshot/internal/merge_internal.h"

#define CMAPER_SNAPSHOT_HOSTNAME_CAP 256

typedef struct {
  const cmaper_nmap_xml_host_t *primary;
  const cmaper_nmap_xml_host_t *secondary;
  const char *ip;
  const char *ip_type;
  const char *status;
  const char *hostname;
  const cmaper_nmap_xml_address_t *mac;
  const cmaper_nmap_xml_port_t *ports;
  size_t port_count;
  const cmaper_nmap_xml_script_t *host_scripts;
  size_t host_script_count;
  const cmaper_nmap_xml_osmatch_t *os_matches;
  size_t os_count;
  const cmaper_nmap_xml_trace_hop_t *trace_hops;
  size_t trace_count;
  const char *observation_source;
  const char *detail_xml_path;
  char inferred_hostname[CMAPER_SNAPSHOT_HOSTNAME_CAP];
} cmaper_snapshot_host_view_t;

cmaper_err_t
cmaper_snapshot_build_host_view(const cmaper_snapshot_merged_host_t *merged,
                                cmaper_snapshot_host_view_t *out_view);

#endif
