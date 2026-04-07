#include "cmaper/scan/internal/detail_targets_internal.h"

#include <stdlib.h>
#include <string.h>

#include "cmaper/scan/nmap_xml_utils.h"

int cmaper_scan_detail_target_compare(const void *left, const void *right) {
  const cmaper_scan_detail_target_t *a =
      (const cmaper_scan_detail_target_t *)left;
  const cmaper_scan_detail_target_t *b =
      (const cmaper_scan_detail_target_t *)right;

  return cmaper_nmap_ip_compare(a->ip, b->ip);
}

static cmaper_err_t cmaper_scan_detail_target_union_ports(
    cmaper_scan_detail_target_t *target,
    const cmaper_scan_detail_target_t *other) {
  size_t i = 0;
  size_t j = 0;
  size_t k = 0;
  int *merged;
  size_t merged_cap;

  if (target == NULL || other == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (other->open_tcp_port_count == 0 || other->open_tcp_ports == NULL) {
    return CMAPER_OK;
  }

  if (target->open_tcp_port_count == 0 || target->open_tcp_ports == NULL) {
    int *copy = (int *)malloc(other->open_tcp_port_count * sizeof(int));
    if (copy == NULL) {
      return CMAPER_ERR_OOM;
    }
    memcpy(copy, other->open_tcp_ports,
           other->open_tcp_port_count * sizeof(int));
    target->open_tcp_ports = copy;
    target->open_tcp_port_count = other->open_tcp_port_count;
    target->has_open_tcp_ports = true;
    return CMAPER_OK;
  }

  merged_cap = target->open_tcp_port_count + other->open_tcp_port_count;
  merged = (int *)malloc(merged_cap * sizeof(int));
  if (merged == NULL) {
    return CMAPER_ERR_OOM;
  }

  while (i < target->open_tcp_port_count && j < other->open_tcp_port_count) {
    int left_port = target->open_tcp_ports[i];
    int right_port = other->open_tcp_ports[j];
    int value;

    if (left_port < right_port) {
      value = left_port;
      i += 1U;
    } else if (left_port > right_port) {
      value = right_port;
      j += 1U;
    } else {
      value = left_port;
      i += 1U;
      j += 1U;
    }

    if (k == 0 || merged[k - 1U] != value) {
      merged[k++] = value;
    }
  }

  while (i < target->open_tcp_port_count) {
    int value = target->open_tcp_ports[i++];
    if (k == 0 || merged[k - 1U] != value) {
      merged[k++] = value;
    }
  }

  while (j < other->open_tcp_port_count) {
    int value = other->open_tcp_ports[j++];
    if (k == 0 || merged[k - 1U] != value) {
      merged[k++] = value;
    }
  }

  free(target->open_tcp_ports);
  target->open_tcp_ports = merged;
  target->open_tcp_port_count = k;
  target->has_open_tcp_ports = (k > 0);

  return CMAPER_OK;
}

cmaper_err_t cmaper_scan_detail_targets_deduplicate(
    cmaper_scan_detail_target_list_t *targets) {
  size_t write_index = 0;
  size_t read_index;

  if (targets == NULL || targets->count == 0 || targets->items == NULL) {
    return CMAPER_OK;
  }

  for (read_index = 0; read_index < targets->count; ++read_index) {
    if (write_index == 0) {
      targets->items[write_index++] = targets->items[read_index];
      continue;
    }

    if (strcmp(targets->items[write_index - 1U].ip,
               targets->items[read_index].ip) != 0) {
      targets->items[write_index++] = targets->items[read_index];
      continue;
    }

    {
      cmaper_err_t rc = cmaper_scan_detail_target_union_ports(
          &targets->items[write_index - 1U], &targets->items[read_index]);
      if (rc != CMAPER_OK) {
        return rc;
      }
    }

    if (targets->items[read_index].open_tcp_ports != NULL) {
      free(targets->items[read_index].open_tcp_ports);
    }
    targets->items[read_index].open_tcp_ports = NULL;
    targets->items[read_index].open_tcp_port_count = 0;
  }

  targets->count = write_index;
  return CMAPER_OK;
}
