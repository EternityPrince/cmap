#ifndef CMAPER_SECURITY_INTERNAL_NMAP_EXTRACT_INTERNAL_H
#define CMAPER_SECURITY_INTERNAL_NMAP_EXTRACT_INTERNAL_H

#include <stdbool.h>

#include "cmaper/security/nmap_extract.h"

cmaper_err_t cmaper_security_nmap_append_fingerprint(
    cmaper_security_host_artifacts_t *artifacts,
    const cmaper_security_fingerprint_t *fingerprint,
    bool has_service_context,
    const char *protocol,
    int port
);

cmaper_err_t cmaper_security_nmap_append_finding(
    cmaper_security_host_artifacts_t *artifacts,
    const cmaper_security_finding_t *finding,
    bool has_service_context,
    const char *protocol,
    int port
);

cmaper_err_t cmaper_security_nmap_append_surface(
    cmaper_security_host_artifacts_t *artifacts,
    const cmaper_security_management_surface_t *surface,
    bool has_service_context,
    const char *protocol,
    int port
);

cmaper_err_t cmaper_security_nmap_extract_from_script(
    cmaper_security_host_artifacts_t *artifacts,
    const cmaper_security_script_input_t *input,
    bool has_service_context
);

#endif
