#ifndef CMAPER_SECURITY_NMAP_EXTRACT_H
#define CMAPER_SECURITY_NMAP_EXTRACT_H

#include <stdbool.h>
#include <stddef.h>

#include "cmaper/core/error.h"
#include "cmaper/scan/nmap_xml_model.h"
#include "cmaper/security/extract.h"

#define CMAPER_SECURITY_PROTOCOL_CAP 8

typedef struct {
    cmaper_security_fingerprint_t fingerprint;
    bool has_service_context;
    char protocol[CMAPER_SECURITY_PROTOCOL_CAP];
    int port;
} cmaper_security_fingerprint_observation_t;

typedef struct {
    cmaper_security_finding_t finding;
    bool has_service_context;
    char protocol[CMAPER_SECURITY_PROTOCOL_CAP];
    int port;
} cmaper_security_finding_observation_t;

typedef struct {
    cmaper_security_management_surface_t surface;
    bool has_service_context;
    char protocol[CMAPER_SECURITY_PROTOCOL_CAP];
    int port;
} cmaper_security_surface_observation_t;

typedef struct {
    cmaper_security_fingerprint_observation_t *fingerprints;
    size_t fingerprint_count;
    cmaper_security_finding_observation_t *findings;
    size_t finding_count;
    cmaper_security_surface_observation_t *surfaces;
    size_t surface_count;
    cmaper_security_aggregate_t aggregate;
} cmaper_security_host_artifacts_t;

void cmaper_security_host_artifacts_init(cmaper_security_host_artifacts_t *artifacts);
void cmaper_security_host_artifacts_dispose(cmaper_security_host_artifacts_t *artifacts);

cmaper_err_t cmaper_security_extract_from_host_pair(
    const cmaper_nmap_xml_host_t *primary_host,
    const cmaper_nmap_xml_host_t *fallback_host,
    cmaper_security_host_artifacts_t *out_artifacts
);

#endif
