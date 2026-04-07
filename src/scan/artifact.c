#include "cmaper/scan/artifact.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "cmaper/platform/fs.h"

static bool cmaper_scan_session_id_is_valid(const char *session_id) {
  size_t i;

  if (session_id == NULL || session_id[0] == '\0') {
    return false;
  }

  for (i = 0; session_id[i] != '\0'; ++i) {
    unsigned char ch = (unsigned char)session_id[i];
    if (isalnum(ch) || ch == '-' || ch == '_' || ch == '.') {
      continue;
    }
    return false;
  }

  return true;
}

static void cmaper_scan_sanitize_component(const char *input, char *output,
                                           size_t output_cap) {
  size_t i;
  size_t j = 0;

  if (output == NULL || output_cap == 0) {
    return;
  }

  output[0] = '\0';
  if (input == NULL || input[0] == '\0') {
    return;
  }

  for (i = 0; input[i] != '\0' && j + 1 < output_cap; ++i) {
    unsigned char ch = (unsigned char)input[i];
    if (isalnum(ch) || ch == '-' || ch == '_' || ch == '.') {
      output[j++] = (char)ch;
    } else {
      output[j++] = '_';
    }
  }

  output[j] = '\0';
}

static cmaper_err_t cmaper_scan_artifact_join_path(char *out, size_t out_cap,
                                                   const char *left,
                                                   const char *right) {
  int written;

  if (out == NULL || out_cap == 0 || left == NULL || right == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (left[0] == '\0' || right[0] == '\0') {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (left[strlen(left) - 1] == '/') {
    written = snprintf(out, out_cap, "%s%s", left, right);
  } else {
    written = snprintf(out, out_cap, "%s/%s", left, right);
  }

  if (written < 0 || (size_t)written >= out_cap) {
    return CMAPER_ERR_IO;
  }

  return CMAPER_OK;
}

static cmaper_err_t cmaper_scan_artifact_resolve_session_xml_dir(
    const cmaper_runtime_paths_t *paths,
    const cmaper_scan_artifact_policy_t *policy, char *out_xml_dir,
    size_t out_xml_dir_cap) {
  char output_root[CMAPER_SCAN_ARTIFACT_PATH_CAP];
  char session_dir[CMAPER_SCAN_ARTIFACT_PATH_CAP];
  cmaper_err_t rc;

  if (paths == NULL || policy == NULL || out_xml_dir == NULL ||
      out_xml_dir_cap == 0) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (!cmaper_scan_session_id_is_valid(policy->session_id)) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  rc = cmaper_fs_parent_directory(paths->xml_output_dir, output_root,
                                  sizeof(output_root));
  if (rc != CMAPER_OK) {
    return rc;
  }

  rc = cmaper_scan_artifact_join_path(session_dir, sizeof(session_dir),
                                      output_root, policy->session_id);
  if (rc != CMAPER_OK) {
    return rc;
  }

  rc = cmaper_scan_artifact_join_path(out_xml_dir, out_xml_dir_cap, session_dir,
                                      "xml");
  if (rc != CMAPER_OK) {
    return rc;
  }

  rc = cmaper_fs_ensure_directory_recursive(out_xml_dir);
  if (rc != CMAPER_OK) {
    return rc;
  }

  return CMAPER_OK;
}

static cmaper_err_t cmaper_scan_artifact_resolve_discovery_xml_path(
    const cmaper_runtime_paths_t *paths,
    const cmaper_scan_artifact_policy_t *policy, char *out_path,
    size_t out_path_cap) {
  char xml_dir[CMAPER_SCAN_ARTIFACT_PATH_CAP];
  cmaper_err_t rc;

  if (paths == NULL || policy == NULL || out_path == NULL ||
      out_path_cap == 0) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  rc = cmaper_scan_artifact_resolve_session_xml_dir(paths, policy, xml_dir,
                                                    sizeof(xml_dir));
  if (rc != CMAPER_OK) {
    return rc;
  }

  return cmaper_scan_artifact_join_path(out_path, out_path_cap, xml_dir,
                                        "discovery.xml");
}

static cmaper_err_t cmaper_scan_artifact_resolve_host_xml_path(
    const cmaper_runtime_paths_t *paths,
    const cmaper_scan_artifact_policy_t *policy, const char *host_ip,
    char *out_path, size_t out_path_cap) {
  char xml_dir[CMAPER_SCAN_ARTIFACT_PATH_CAP];
  char host_component[CMAPER_SCAN_ARTIFACT_PATH_CAP];
  char file_name[CMAPER_SCAN_ARTIFACT_PATH_CAP];
  cmaper_err_t rc;

  if (paths == NULL || policy == NULL || host_ip == NULL || out_path == NULL ||
      out_path_cap == 0) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  rc = cmaper_scan_artifact_resolve_session_xml_dir(paths, policy, xml_dir,
                                                    sizeof(xml_dir));
  if (rc != CMAPER_OK) {
    return rc;
  }

  cmaper_scan_sanitize_component(host_ip, host_component,
                                 sizeof(host_component));
  if (host_component[0] == '\0') {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (snprintf(file_name, sizeof(file_name), "host-%s.xml", host_component) >=
      (int)sizeof(file_name)) {
    return CMAPER_ERR_IO;
  }

  return cmaper_scan_artifact_join_path(out_path, out_path_cap, xml_dir,
                                        file_name);
}

static cmaper_err_t cmaper_scan_artifact_copy_file(const char *source_path,
                                                   const char *target_path) {
  FILE *source = NULL;
  FILE *target = NULL;
  char buffer[8192];
  size_t read_size;
  cmaper_err_t rc = CMAPER_OK;

  if (source_path == NULL || source_path[0] == '\0' || target_path == NULL ||
      target_path[0] == '\0') {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  source = fopen(source_path, "rb");
  if (source == NULL) {
    return CMAPER_ERR_IO;
  }

  target = fopen(target_path, "wb");
  if (target == NULL) {
    fclose(source);
    return CMAPER_ERR_IO;
  }

  while ((read_size = fread(buffer, 1, sizeof(buffer), source)) > 0) {
    if (fwrite(buffer, 1, read_size, target) != read_size) {
      rc = CMAPER_ERR_IO;
      break;
    }
  }
  if (ferror(source)) {
    rc = CMAPER_ERR_IO;
  }

  if (fclose(source) != 0) {
    rc = CMAPER_ERR_IO;
  }
  if (fclose(target) != 0) {
    rc = CMAPER_ERR_IO;
  }

  return rc;
}

cmaper_err_t cmaper_scan_artifact_save_discovery_xml(
    const cmaper_runtime_paths_t *paths,
    const cmaper_scan_artifact_policy_t *policy, const char *xml_data,
    size_t xml_size, char *out_path, size_t out_path_cap) {
  FILE *file;
  size_t written_size;
  cmaper_err_t rc;

  if (out_path != NULL && out_path_cap > 0) {
    out_path[0] = '\0';
  }

  if (paths == NULL || policy == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (!policy->save_discovery_xml) {
    return CMAPER_OK;
  }

  if (!cmaper_scan_session_id_is_valid(policy->session_id)) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (xml_data == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (out_path == NULL || out_path_cap == 0) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  rc = cmaper_scan_artifact_resolve_discovery_xml_path(paths, policy, out_path,
                                                       out_path_cap);
  if (rc != CMAPER_OK) {
    return rc;
  }

  file = fopen(out_path, "wb");
  if (file == NULL) {
    return CMAPER_ERR_IO;
  }

  written_size = fwrite(xml_data, 1, xml_size, file);
  if (written_size != xml_size) {
    fclose(file);
    return CMAPER_ERR_IO;
  }

  if (fclose(file) != 0) {
    return CMAPER_ERR_IO;
  }

  return CMAPER_OK;
}

cmaper_err_t cmaper_scan_artifact_save_discovery_xml_file(
    const cmaper_runtime_paths_t *paths,
    const cmaper_scan_artifact_policy_t *policy, const char *source_path,
    char *out_path, size_t out_path_cap) {
  cmaper_err_t rc;

  if (out_path != NULL && out_path_cap > 0) {
    out_path[0] = '\0';
  }

  if (paths == NULL || policy == NULL || source_path == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (!policy->save_discovery_xml) {
    return CMAPER_OK;
  }

  if (out_path == NULL || out_path_cap == 0) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  rc = cmaper_scan_artifact_resolve_discovery_xml_path(paths, policy, out_path,
                                                       out_path_cap);
  if (rc != CMAPER_OK) {
    return rc;
  }

  return cmaper_scan_artifact_copy_file(source_path, out_path);
}

cmaper_err_t
cmaper_scan_artifact_save_host_xml(const cmaper_runtime_paths_t *paths,
                                   const cmaper_scan_artifact_policy_t *policy,
                                   const char *host_ip, const char *xml_data,
                                   size_t xml_size, char *out_path,
                                   size_t out_path_cap) {
  FILE *file;
  size_t written_size;
  cmaper_err_t rc;

  if (out_path != NULL && out_path_cap > 0) {
    out_path[0] = '\0';
  }

  if (paths == NULL || policy == NULL || host_ip == NULL || xml_data == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (!policy->save_host_xml) {
    return CMAPER_OK;
  }

  if (out_path == NULL || out_path_cap == 0) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  rc = cmaper_scan_artifact_resolve_host_xml_path(paths, policy, host_ip,
                                                  out_path, out_path_cap);
  if (rc != CMAPER_OK) {
    return rc;
  }

  file = fopen(out_path, "wb");
  if (file == NULL) {
    return CMAPER_ERR_IO;
  }

  written_size = fwrite(xml_data, 1, xml_size, file);
  if (written_size != xml_size) {
    fclose(file);
    return CMAPER_ERR_IO;
  }

  if (fclose(file) != 0) {
    return CMAPER_ERR_IO;
  }

  return CMAPER_OK;
}

cmaper_err_t cmaper_scan_artifact_save_host_xml_file(
    const cmaper_runtime_paths_t *paths,
    const cmaper_scan_artifact_policy_t *policy, const char *host_ip,
    const char *source_path, char *out_path, size_t out_path_cap) {
  cmaper_err_t rc;

  if (out_path != NULL && out_path_cap > 0) {
    out_path[0] = '\0';
  }

  if (paths == NULL || policy == NULL || host_ip == NULL ||
      source_path == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (!policy->save_host_xml) {
    return CMAPER_OK;
  }

  if (out_path == NULL || out_path_cap == 0) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  rc = cmaper_scan_artifact_resolve_host_xml_path(paths, policy, host_ip,
                                                  out_path, out_path_cap);
  if (rc != CMAPER_OK) {
    return rc;
  }

  return cmaper_scan_artifact_copy_file(source_path, out_path);
}
