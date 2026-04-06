#include "cmaper/security/nmap_extract.h"

#include <stdlib.h>
#include <string.h>

#include "cmaper/security/internal/nmap_extract_internal.h"

void cmaper_security_host_artifacts_init(cmaper_security_host_artifacts_t *artifacts) {
    if (artifacts == NULL) {
        return;
    }

    artifacts->fingerprints = NULL;
    artifacts->fingerprint_count = 0;
    artifacts->findings = NULL;
    artifacts->finding_count = 0;
    artifacts->surfaces = NULL;
    artifacts->surface_count = 0;
    cmaper_security_aggregate_init(&artifacts->aggregate);
}

void cmaper_security_host_artifacts_dispose(cmaper_security_host_artifacts_t *artifacts) {
    if (artifacts == NULL) {
        return;
    }

    if (artifacts->fingerprints != NULL) {
        free(artifacts->fingerprints);
        artifacts->fingerprints = NULL;
    }
    artifacts->fingerprint_count = 0;

    if (artifacts->findings != NULL) {
        free(artifacts->findings);
        artifacts->findings = NULL;
    }
    artifacts->finding_count = 0;

    if (artifacts->surfaces != NULL) {
        free(artifacts->surfaces);
        artifacts->surfaces = NULL;
    }
    artifacts->surface_count = 0;
    cmaper_security_aggregate_init(&artifacts->aggregate);
}

cmaper_err_t cmaper_security_extract_from_host_pair(
    const cmaper_nmap_xml_host_t *primary_host,
    const cmaper_nmap_xml_host_t *fallback_host,
    cmaper_security_host_artifacts_t *out_artifacts
) {
    const cmaper_nmap_xml_script_t *host_scripts = NULL;
    size_t host_script_count = 0;
    const cmaper_nmap_xml_port_t *ports = NULL;
    size_t port_count = 0;
    size_t i;
    cmaper_err_t rc;

    if (out_artifacts == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_security_host_artifacts_dispose(out_artifacts);
    cmaper_security_host_artifacts_init(out_artifacts);

    if (primary_host != NULL && primary_host->host_script_count > 0) {
        host_scripts = primary_host->host_scripts;
        host_script_count = primary_host->host_script_count;
    } else if (fallback_host != NULL && fallback_host->host_script_count > 0) {
        host_scripts = fallback_host->host_scripts;
        host_script_count = fallback_host->host_script_count;
    }

    if (primary_host != NULL && primary_host->port_count > 0) {
        ports = primary_host->ports;
        port_count = primary_host->port_count;
    } else if (fallback_host != NULL && fallback_host->port_count > 0) {
        ports = fallback_host->ports;
        port_count = fallback_host->port_count;
    }

    for (i = 0; i < host_script_count; ++i) {
        cmaper_security_script_input_t input;
        cmaper_security_script_input_init(&input);
        input.script_id = host_scripts[i].id;
        input.output = host_scripts[i].output;

        rc = cmaper_security_nmap_extract_from_script(out_artifacts, &input, false);
        if (rc != CMAPER_OK) {
            cmaper_security_host_artifacts_dispose(out_artifacts);
            return rc;
        }
    }

    for (i = 0; i < port_count; ++i) {
        const cmaper_nmap_xml_port_t *port = &ports[i];
        cmaper_security_management_surface_t surfaces[8];
        size_t surface_count;
        size_t j;

        if (port->portid <= 0 || port->protocol == NULL || port->protocol[0] == '\0') {
            continue;
        }

        surface_count = cmaper_security_detect_management_surfaces_for_port(
            port->protocol,
            port->portid,
            port->service_name,
            surfaces,
            sizeof(surfaces) / sizeof(surfaces[0])
        );
        for (j = 0; j < surface_count; ++j) {
            rc = cmaper_security_nmap_append_surface(
                out_artifacts,
                &surfaces[j],
                true,
                port->protocol,
                port->portid
            );
            if (rc != CMAPER_OK) {
                cmaper_security_host_artifacts_dispose(out_artifacts);
                return rc;
            }
        }

        for (j = 0; j < port->script_count; ++j) {
            cmaper_security_script_input_t input;
            cmaper_security_script_input_init(&input);
            input.script_id = port->scripts[j].id;
            input.output = port->scripts[j].output;
            input.protocol = port->protocol;
            input.port = port->portid;
            input.service_name = port->service_name;

            rc = cmaper_security_nmap_extract_from_script(out_artifacts, &input, true);
            if (rc != CMAPER_OK) {
                cmaper_security_host_artifacts_dispose(out_artifacts);
                return rc;
            }
        }
    }

    return CMAPER_OK;
}
