#include "cmaper/security/extract.h"

#include <stdio.h>
#include <string.h>

#include "cmaper/security/internal/extract_internal.h"

typedef struct {
  int port;
  const char *type;
  const char *detail;
} cmaper_security_well_known_surface_t;

static const cmaper_security_well_known_surface_t
    CMAPER_SECURITY_WELL_KNOWN_SURFACES[] = {
        {22, "ssh", "Well-known SSH management surface"},
        {23, "telnet", "Well-known Telnet management surface"},
        {80, "web-http", "Well-known HTTP web surface"},
        {443, "web-https", "Well-known HTTPS web surface"},
        {445, "smb", "SMB remote management/file-sharing surface"},
        {3389, "rdp", "RDP remote desktop surface"},
        {5900, "vnc", "VNC remote desktop surface"},
        {5901, "vnc", "VNC remote desktop surface"},
        {5902, "vnc", "VNC remote desktop surface"},
        {5903, "vnc", "VNC remote desktop surface"},
        {5985, "winrm-http", "WinRM management surface"},
        {5986, "winrm-https", "WinRM TLS management surface"},
        {6443, "k8s-api", "Kubernetes API surface"},
        {2375, "docker-api", "Docker API management surface"},
        {2376, "docker-api-tls", "Docker TLS API management surface"}};

static bool
cmaper_security_append_surface(cmaper_security_management_surface_t *out_items,
                               size_t out_cap, size_t *in_out_count,
                               const char *type, const char *detail) {
  size_t i;

  if (out_items == NULL || in_out_count == NULL || type == NULL ||
      detail == NULL) {
    return false;
  }

  for (i = 0; i < *in_out_count; ++i) {
    if (strcmp(out_items[i].type, type) == 0 &&
        strcmp(out_items[i].detail, detail) == 0) {
      return true;
    }
  }

  if (*in_out_count >= out_cap) {
    return false;
  }

  cmaper_security_management_surface_init(&out_items[*in_out_count]);
  cmaper_security_copy_string(out_items[*in_out_count].type,
                              sizeof(out_items[*in_out_count].type), type);
  cmaper_security_copy_string(out_items[*in_out_count].detail,
                              sizeof(out_items[*in_out_count].detail), detail);
  *in_out_count += 1U;
  return true;
}

size_t cmaper_security_detect_management_surfaces_for_port(
    const char *protocol, int port, const char *service_name,
    cmaper_security_management_surface_t *out_items, size_t out_cap) {
  size_t i;
  size_t count = 0;

  if (out_items == NULL || out_cap == 0 || port <= 0) {
    return 0;
  }

  if (protocol != NULL && protocol[0] != '\0') {
    if (!cmaper_security_starts_with_ci(protocol, "tcp") &&
        !cmaper_security_starts_with_ci(protocol, "udp")) {
      return 0;
    }
  }

  for (i = 0; i < sizeof(CMAPER_SECURITY_WELL_KNOWN_SURFACES) /
                      sizeof(CMAPER_SECURITY_WELL_KNOWN_SURFACES[0]);
       ++i) {
    if (CMAPER_SECURITY_WELL_KNOWN_SURFACES[i].port != port) {
      continue;
    }
    (void)cmaper_security_append_surface(
        out_items, out_cap, &count, CMAPER_SECURITY_WELL_KNOWN_SURFACES[i].type,
        CMAPER_SECURITY_WELL_KNOWN_SURFACES[i].detail);
  }

  if (service_name != NULL && service_name[0] != '\0') {
    if (cmaper_security_contains_ci(service_name, "http") && port != 80 &&
        port != 443 && port != 8080 && port != 8443) {
      (void)cmaper_security_append_surface(
          out_items, out_cap, &count, "web-http",
          "HTTP service-detected management/web surface");
    }
    if (cmaper_security_contains_ci(service_name, "https") && port != 443 &&
        port != 8443) {
      (void)cmaper_security_append_surface(
          out_items, out_cap, &count, "web-https",
          "HTTPS service-detected management/web surface");
    }
  }

  return count;
}

size_t cmaper_security_detect_management_surfaces_from_http_title(
    const cmaper_security_script_input_t *input,
    cmaper_security_management_surface_t *out_items, size_t out_cap) {
  static const char *KEYWORDS[] = {
      "login",   "admin",  "dashboard", "management", "panel",
      "console", "webmin", "router",    "camera",     "drac",
      "ilo",     "ipmi",   "grafana",   "kibana"};
  char title[CMAPER_SECURITY_SURFACE_DETAIL_CAP];
  char normalized[CMAPER_SECURITY_SURFACE_DETAIL_CAP];
  size_t i;
  size_t count = 0;
  const char *surface_type = "web-admin-http";

  if (input == NULL || input->output == NULL || out_items == NULL ||
      out_cap == 0) {
    return 0;
  }
  if (input->script_id == NULL ||
      !cmaper_security_contains_ci(input->script_id, "http-title")) {
    return 0;
  }
  if (!cmaper_security_extract_first_text_line(input->output, title,
                                               sizeof(title))) {
    return 0;
  }

  cmaper_security_normalize_spaces(title, normalized, sizeof(normalized), true);
  if (normalized[0] == '\0') {
    return 0;
  }

  if ((input->port == 443 || input->port == 8443) ||
      cmaper_security_contains_ci(input->service_name, "https")) {
    surface_type = "web-admin-https";
  }

  for (i = 0; i < sizeof(KEYWORDS) / sizeof(KEYWORDS[0]); ++i) {
    if (!cmaper_security_contains_ci(normalized, KEYWORDS[i])) {
      continue;
    }

    {
      char detail[CMAPER_SECURITY_SURFACE_DETAIL_CAP];
      snprintf(detail, sizeof(detail), "HTTP title hint: %s", title);
      (void)cmaper_security_append_surface(out_items, out_cap, &count,
                                           surface_type, detail);
    }
    break;
  }

  return count;
}
