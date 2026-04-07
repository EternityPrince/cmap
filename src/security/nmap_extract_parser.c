#include "cmaper/security/internal/nmap_extract_internal.h"

cmaper_err_t cmaper_security_nmap_extract_from_script(
    cmaper_security_host_artifacts_t *artifacts,
    const cmaper_security_script_input_t *input, bool has_service_context) {
  cmaper_security_fingerprint_t fingerprint;
  cmaper_security_finding_t findings[8];
  cmaper_security_management_surface_t surfaces[4];
  size_t finding_count;
  size_t surface_count;
  size_t i;
  cmaper_err_t rc;

  if (artifacts == NULL || input == NULL || input->script_id == NULL ||
      input->output == NULL) {
    return CMAPER_OK;
  }

  cmaper_security_fingerprint_init(&fingerprint);
  if (cmaper_security_normalize_tls_fingerprint(input, &fingerprint)) {
    rc = cmaper_security_nmap_append_fingerprint(artifacts, &fingerprint,
                                                 has_service_context,
                                                 input->protocol, input->port);
    if (rc != CMAPER_OK) {
      return rc;
    }
  }

  cmaper_security_fingerprint_init(&fingerprint);
  if (cmaper_security_normalize_ssh_fingerprint(input, &fingerprint)) {
    rc = cmaper_security_nmap_append_fingerprint(artifacts, &fingerprint,
                                                 has_service_context,
                                                 input->protocol, input->port);
    if (rc != CMAPER_OK) {
      return rc;
    }
  }

  cmaper_security_fingerprint_init(&fingerprint);
  if (cmaper_security_normalize_http_fingerprint(input, &fingerprint)) {
    rc = cmaper_security_nmap_append_fingerprint(artifacts, &fingerprint,
                                                 has_service_context,
                                                 input->protocol, input->port);
    if (rc != CMAPER_OK) {
      return rc;
    }
  }

  cmaper_security_fingerprint_init(&fingerprint);
  if (cmaper_security_normalize_smb_fingerprint(input, &fingerprint)) {
    rc = cmaper_security_nmap_append_fingerprint(artifacts, &fingerprint,
                                                 has_service_context,
                                                 input->protocol, input->port);
    if (rc != CMAPER_OK) {
      return rc;
    }
  }

  finding_count = cmaper_security_extract_findings(
      input, findings, sizeof(findings) / sizeof(findings[0]));
  for (i = 0; i < finding_count; ++i) {
    rc = cmaper_security_nmap_append_finding(artifacts, &findings[i],
                                             has_service_context,
                                             input->protocol, input->port);
    if (rc != CMAPER_OK) {
      return rc;
    }
  }

  surface_count = cmaper_security_detect_management_surfaces_from_http_title(
      input, surfaces, sizeof(surfaces) / sizeof(surfaces[0]));
  for (i = 0; i < surface_count; ++i) {
    rc = cmaper_security_nmap_append_surface(artifacts, &surfaces[i],
                                             has_service_context,
                                             input->protocol, input->port);
    if (rc != CMAPER_OK) {
      return rc;
    }
  }

  return CMAPER_OK;
}
