#include "cmaper/snapshot/internal/merge_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmaper/scan/nmap_xml_parse.h"
#include "cmaper/scan/nmap_xml_utils.h"

static cmaper_err_t cmaper_snapshot_read_file(const char *path, char **out_data,
                                              size_t *out_size) {
  FILE *file;
  long file_size_long;
  size_t file_size;
  char *buffer;
  size_t read_size;

  if (path == NULL || out_data == NULL || out_size == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_data = NULL;
  *out_size = 0;

  file = fopen(path, "rb");
  if (file == NULL) {
    return CMAPER_ERR_IO;
  }

  if (fseek(file, 0L, SEEK_END) != 0) {
    fclose(file);
    return CMAPER_ERR_IO;
  }

  file_size_long = ftell(file);
  if (file_size_long < 0) {
    fclose(file);
    return CMAPER_ERR_IO;
  }
  file_size = (size_t)file_size_long;

  if (fseek(file, 0L, SEEK_SET) != 0) {
    fclose(file);
    return CMAPER_ERR_IO;
  }

  buffer = (char *)malloc(file_size + 1U);
  if (buffer == NULL) {
    fclose(file);
    return CMAPER_ERR_OOM;
  }

  read_size = fread(buffer, 1, file_size, file);
  if (read_size != file_size) {
    free(buffer);
    fclose(file);
    return CMAPER_ERR_IO;
  }

  if (fclose(file) != 0) {
    free(buffer);
    return CMAPER_ERR_IO;
  }

  buffer[file_size] = '\0';
  *out_data = buffer;
  *out_size = file_size;
  return CMAPER_OK;
}

static const cmaper_nmap_xml_host_t *cmaper_snapshot_find_host_in_document(
    const cmaper_nmap_xml_document_t *document, const char *expected_ip) {
  const cmaper_nmap_xml_host_t *fallback_up = NULL;
  size_t i;

  if (document == NULL) {
    return NULL;
  }

  for (i = 0; i < document->host_count; ++i) {
    const cmaper_nmap_xml_host_t *host = &document->hosts[i];
    const char *ip = cmaper_nmap_host_primary_ip(host);
    if (ip != NULL && expected_ip != NULL && strcmp(ip, expected_ip) == 0) {
      return host;
    }
    if (fallback_up == NULL && host->status.state != NULL &&
        strcmp(host->status.state, "up") == 0) {
      fallback_up = host;
    }
  }

  if (fallback_up != NULL) {
    return fallback_up;
  }
  if (document->host_count > 0) {
    return &document->hosts[0];
  }

  return NULL;
}

static int cmaper_snapshot_merged_host_compare(const void *left,
                                               const void *right) {
  const cmaper_snapshot_merged_host_t *a =
      (const cmaper_snapshot_merged_host_t *)left;
  const cmaper_snapshot_merged_host_t *b =
      (const cmaper_snapshot_merged_host_t *)right;
  return cmaper_nmap_ip_compare(a->ip, b->ip);
}

static const cmaper_snapshot_detail_doc_t *
cmaper_snapshot_find_detail_doc_for_ip(
    const cmaper_snapshot_detail_doc_t *items, size_t count, const char *ip) {
  size_t i;

  if (items == NULL || ip == NULL || ip[0] == '\0') {
    return NULL;
  }

  for (i = 0; i < count; ++i) {
    if (!items[i].loaded || items[i].ip[0] == '\0') {
      continue;
    }
    if (strcmp(items[i].ip, ip) == 0) {
      return &items[i];
    }
  }

  return NULL;
}

static cmaper_err_t cmaper_snapshot_append_or_merge_merged_host(
    cmaper_snapshot_merged_host_t **items, size_t *count, const char *ip,
    const cmaper_nmap_xml_host_t *discovery_host,
    const cmaper_snapshot_detail_doc_t *detail_doc) {
  size_t i;
  cmaper_snapshot_merged_host_t *next;

  if (items == NULL || count == NULL || ip == NULL || ip[0] == '\0') {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  for (i = 0; i < *count; ++i) {
    if (strcmp((*items)[i].ip, ip) != 0) {
      continue;
    }

    if ((*items)[i].discovery_host == NULL && discovery_host != NULL) {
      (*items)[i].discovery_host = discovery_host;
    }
    if ((*items)[i].detail_doc == NULL && detail_doc != NULL) {
      (*items)[i].detail_doc = detail_doc;
    }
    return CMAPER_OK;
  }

  next = (cmaper_snapshot_merged_host_t *)realloc(
      *items, (*count + 1U) * sizeof(cmaper_snapshot_merged_host_t));
  if (next == NULL) {
    return CMAPER_ERR_OOM;
  }

  *items = next;
  snprintf((*items)[*count].ip, sizeof((*items)[*count].ip), "%s", ip);
  (*items)[*count].discovery_host = discovery_host;
  (*items)[*count].detail_doc = detail_doc;
  *count += 1U;

  return CMAPER_OK;
}

void cmaper_snapshot_detail_docs_dispose(cmaper_snapshot_detail_doc_t *items,
                                         size_t count) {
  size_t i;

  if (items == NULL) {
    return;
  }

  for (i = 0; i < count; ++i) {
    if (items[i].loaded) {
      cmaper_nmap_xml_document_dispose(&items[i].document);
      cmaper_nmap_xml_document_init(&items[i].document);
      items[i].loaded = false;
    }
  }

  free(items);
}

void cmaper_snapshot_merged_hosts_dispose(
    cmaper_snapshot_merged_host_t *items) {
  if (items == NULL) {
    return;
  }

  free(items);
}

cmaper_err_t
cmaper_snapshot_build_detail_docs(const cmaper_scan_result_t *scan_result,
                                  cmaper_snapshot_detail_doc_t **out_items,
                                  size_t *out_count, cmaper_logger_t *logger) {
  size_t i;
  size_t capacity;
  size_t count = 0;
  cmaper_snapshot_detail_doc_t *items = NULL;

  if (scan_result == NULL || out_items == NULL || out_count == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_items = NULL;
  *out_count = 0;

  capacity = scan_result->detail_result.host_count;
  if (capacity == 0) {
    return CMAPER_OK;
  }

  items = (cmaper_snapshot_detail_doc_t *)calloc(
      capacity, sizeof(cmaper_snapshot_detail_doc_t));
  if (items == NULL) {
    return CMAPER_ERR_OOM;
  }

  for (i = 0; i < scan_result->detail_result.host_count; ++i) {
    const cmaper_scan_detail_host_result_t *host_result =
        &scan_result->detail_result.hosts[i];
    char *xml_data = NULL;
    size_t xml_size = 0;
    cmaper_nmap_xml_diag_t xml_diag;
    cmaper_err_t rc;

    if (!host_result->success || host_result->xml_path[0] == '\0') {
      continue;
    }

    rc = cmaper_snapshot_read_file(host_result->xml_path, &xml_data, &xml_size);
    if (rc != CMAPER_OK) {
      cmaper_log(logger, CMAPER_LOG_WARN,
                 "snapshot/write: failed to read host xml '%s'",
                 host_result->xml_path);
      continue;
    }

    cmaper_nmap_xml_document_init(&items[count].document);
    cmaper_nmap_xml_diag_clear(&xml_diag);

    rc = cmaper_nmap_xml_parse_memory(xml_data, xml_size,
                                      &items[count].document, &xml_diag);
    free(xml_data);
    xml_data = NULL;

    if (rc != CMAPER_OK) {
      cmaper_log(logger, CMAPER_LOG_WARN,
                 "snapshot/write: failed to parse host xml '%s': %s",
                 host_result->xml_path,
                 xml_diag.message[0] != '\0' ? xml_diag.message
                                             : "parse error");
      cmaper_nmap_xml_document_dispose(&items[count].document);
      continue;
    }

    snprintf(items[count].ip, sizeof(items[count].ip), "%s", host_result->ip);
    snprintf(items[count].xml_path, sizeof(items[count].xml_path), "%s",
             host_result->xml_path);
    items[count].host = cmaper_snapshot_find_host_in_document(
        &items[count].document, host_result->ip);
    items[count].loaded = true;
    count += 1U;
  }

  *out_items = items;
  *out_count = count;
  return CMAPER_OK;
}

cmaper_err_t cmaper_snapshot_build_merged_hosts(
    const cmaper_nmap_xml_document_t *discovery_doc,
    const cmaper_snapshot_detail_doc_t *detail_docs, size_t detail_doc_count,
    cmaper_snapshot_merged_host_t **out_items, size_t *out_count) {
  cmaper_snapshot_merged_host_t *items = NULL;
  size_t count = 0;
  size_t i;
  cmaper_err_t rc;

  if (discovery_doc == NULL || out_items == NULL || out_count == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_items = NULL;
  *out_count = 0;

  for (i = 0; i < discovery_doc->host_count; ++i) {
    const cmaper_nmap_xml_host_t *host = &discovery_doc->hosts[i];
    const char *ip = cmaper_nmap_host_primary_ip(host);
    const cmaper_snapshot_detail_doc_t *detail_doc;

    if (ip == NULL || ip[0] == '\0') {
      continue;
    }

    detail_doc = cmaper_snapshot_find_detail_doc_for_ip(detail_docs,
                                                        detail_doc_count, ip);
    rc = cmaper_snapshot_append_or_merge_merged_host(&items, &count, ip, host,
                                                     detail_doc);
    if (rc != CMAPER_OK) {
      cmaper_snapshot_merged_hosts_dispose(items);
      return rc;
    }
  }

  for (i = 0; i < detail_doc_count; ++i) {
    if (!detail_docs[i].loaded || detail_docs[i].host == NULL ||
        detail_docs[i].ip[0] == '\0') {
      continue;
    }

    rc = cmaper_snapshot_append_or_merge_merged_host(
        &items, &count, detail_docs[i].ip, NULL, &detail_docs[i]);
    if (rc != CMAPER_OK) {
      cmaper_snapshot_merged_hosts_dispose(items);
      return rc;
    }
  }

  if (count > 1U) {
    qsort(items, count, sizeof(cmaper_snapshot_merged_host_t),
          cmaper_snapshot_merged_host_compare);
  }

  *out_items = items;
  *out_count = count;
  return CMAPER_OK;
}
