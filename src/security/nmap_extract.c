#include "cmaper/security/nmap_extract.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void cmaper_security_copy_protocol(char *out, size_t out_cap, const char *protocol) {
    if (out == NULL || out_cap == 0) {
        return;
    }

    out[0] = '\0';
    if (protocol == NULL) {
        return;
    }

    snprintf(out, out_cap, "%s", protocol);
}

static bool cmaper_security_context_matches(
    bool left_has_context,
    const char *left_protocol,
    int left_port,
    bool right_has_context,
    const char *right_protocol,
    int right_port
) {
    if (left_has_context != right_has_context) {
        return false;
    }

    if (!left_has_context) {
        return true;
    }

    if (left_port != right_port) {
        return false;
    }

    if (left_protocol == NULL || right_protocol == NULL) {
        return left_protocol == right_protocol;
    }

    return strcmp(left_protocol, right_protocol) == 0;
}

static cmaper_err_t cmaper_security_append_fingerprint(
    cmaper_security_host_artifacts_t *artifacts,
    const cmaper_security_fingerprint_t *fingerprint,
    bool has_service_context,
    const char *protocol,
    int port
) {
    cmaper_security_fingerprint_observation_t *next;
    size_t i;

    if (artifacts == NULL || fingerprint == NULL || fingerprint->value[0] == '\0') {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    for (i = 0; i < artifacts->fingerprint_count; ++i) {
        const cmaper_security_fingerprint_observation_t *existing = &artifacts->fingerprints[i];
        if (existing->fingerprint.kind != fingerprint->kind) {
            continue;
        }
        if (strcmp(existing->fingerprint.value, fingerprint->value) != 0) {
            continue;
        }
        if (!cmaper_security_context_matches(
                existing->has_service_context,
                existing->protocol,
                existing->port,
                has_service_context,
                protocol,
                port)) {
            continue;
        }
        return CMAPER_OK;
    }

    next = (cmaper_security_fingerprint_observation_t *) realloc(
        artifacts->fingerprints,
        (artifacts->fingerprint_count + 1U) * sizeof(cmaper_security_fingerprint_observation_t)
    );
    if (next == NULL) {
        return CMAPER_ERR_OOM;
    }
    artifacts->fingerprints = next;

    artifacts->fingerprints[artifacts->fingerprint_count].fingerprint = *fingerprint;
    artifacts->fingerprints[artifacts->fingerprint_count].has_service_context = has_service_context;
    artifacts->fingerprints[artifacts->fingerprint_count].port = has_service_context ? port : 0;
    cmaper_security_copy_protocol(
        artifacts->fingerprints[artifacts->fingerprint_count].protocol,
        sizeof(artifacts->fingerprints[artifacts->fingerprint_count].protocol),
        has_service_context ? protocol : NULL
    );
    artifacts->fingerprint_count += 1U;
    cmaper_security_aggregate_add_fingerprint(&artifacts->aggregate, fingerprint);
    return CMAPER_OK;
}

static cmaper_err_t cmaper_security_append_finding(
    cmaper_security_host_artifacts_t *artifacts,
    const cmaper_security_finding_t *finding,
    bool has_service_context,
    const char *protocol,
    int port
) {
    cmaper_security_finding_observation_t *next;
    size_t i;

    if (artifacts == NULL || finding == NULL || finding->key[0] == '\0') {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    for (i = 0; i < artifacts->finding_count; ++i) {
        const cmaper_security_finding_observation_t *existing = &artifacts->findings[i];
        if (strcmp(existing->finding.key, finding->key) != 0) {
            continue;
        }
        if (!cmaper_security_context_matches(
                existing->has_service_context,
                existing->protocol,
                existing->port,
                has_service_context,
                protocol,
                port)) {
            continue;
        }
        return CMAPER_OK;
    }

    next = (cmaper_security_finding_observation_t *) realloc(
        artifacts->findings,
        (artifacts->finding_count + 1U) * sizeof(cmaper_security_finding_observation_t)
    );
    if (next == NULL) {
        return CMAPER_ERR_OOM;
    }
    artifacts->findings = next;

    artifacts->findings[artifacts->finding_count].finding = *finding;
    artifacts->findings[artifacts->finding_count].has_service_context = has_service_context;
    artifacts->findings[artifacts->finding_count].port = has_service_context ? port : 0;
    cmaper_security_copy_protocol(
        artifacts->findings[artifacts->finding_count].protocol,
        sizeof(artifacts->findings[artifacts->finding_count].protocol),
        has_service_context ? protocol : NULL
    );
    artifacts->finding_count += 1U;
    cmaper_security_aggregate_add_finding(&artifacts->aggregate, finding);
    return CMAPER_OK;
}

static cmaper_err_t cmaper_security_append_surface(
    cmaper_security_host_artifacts_t *artifacts,
    const cmaper_security_management_surface_t *surface,
    bool has_service_context,
    const char *protocol,
    int port
) {
    cmaper_security_surface_observation_t *next;
    size_t i;

    if (artifacts == NULL || surface == NULL || surface->type[0] == '\0') {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    for (i = 0; i < artifacts->surface_count; ++i) {
        const cmaper_security_surface_observation_t *existing = &artifacts->surfaces[i];
        if (strcmp(existing->surface.type, surface->type) != 0) {
            continue;
        }
        if (strcmp(existing->surface.detail, surface->detail) != 0) {
            continue;
        }
        if (!cmaper_security_context_matches(
                existing->has_service_context,
                existing->protocol,
                existing->port,
                has_service_context,
                protocol,
                port)) {
            continue;
        }
        return CMAPER_OK;
    }

    next = (cmaper_security_surface_observation_t *) realloc(
        artifacts->surfaces,
        (artifacts->surface_count + 1U) * sizeof(cmaper_security_surface_observation_t)
    );
    if (next == NULL) {
        return CMAPER_ERR_OOM;
    }
    artifacts->surfaces = next;

    artifacts->surfaces[artifacts->surface_count].surface = *surface;
    artifacts->surfaces[artifacts->surface_count].has_service_context = has_service_context;
    artifacts->surfaces[artifacts->surface_count].port = has_service_context ? port : 0;
    cmaper_security_copy_protocol(
        artifacts->surfaces[artifacts->surface_count].protocol,
        sizeof(artifacts->surfaces[artifacts->surface_count].protocol),
        has_service_context ? protocol : NULL
    );
    artifacts->surface_count += 1U;
    cmaper_security_aggregate_add_surface(&artifacts->aggregate, surface);
    return CMAPER_OK;
}

static cmaper_err_t cmaper_security_extract_from_script(
    cmaper_security_host_artifacts_t *artifacts,
    const cmaper_security_script_input_t *input,
    bool has_service_context
) {
    cmaper_security_fingerprint_t fingerprint;
    cmaper_security_finding_t findings[8];
    cmaper_security_management_surface_t surfaces[4];
    size_t finding_count;
    size_t surface_count;
    size_t i;
    cmaper_err_t rc;

    if (artifacts == NULL || input == NULL || input->script_id == NULL || input->output == NULL) {
        return CMAPER_OK;
    }

    cmaper_security_fingerprint_init(&fingerprint);
    if (cmaper_security_normalize_tls_fingerprint(input, &fingerprint)) {
        rc = cmaper_security_append_fingerprint(
            artifacts,
            &fingerprint,
            has_service_context,
            input->protocol,
            input->port
        );
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    cmaper_security_fingerprint_init(&fingerprint);
    if (cmaper_security_normalize_ssh_fingerprint(input, &fingerprint)) {
        rc = cmaper_security_append_fingerprint(
            artifacts,
            &fingerprint,
            has_service_context,
            input->protocol,
            input->port
        );
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    cmaper_security_fingerprint_init(&fingerprint);
    if (cmaper_security_normalize_http_fingerprint(input, &fingerprint)) {
        rc = cmaper_security_append_fingerprint(
            artifacts,
            &fingerprint,
            has_service_context,
            input->protocol,
            input->port
        );
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    cmaper_security_fingerprint_init(&fingerprint);
    if (cmaper_security_normalize_smb_fingerprint(input, &fingerprint)) {
        rc = cmaper_security_append_fingerprint(
            artifacts,
            &fingerprint,
            has_service_context,
            input->protocol,
            input->port
        );
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    finding_count = cmaper_security_extract_findings(
        input,
        findings,
        sizeof(findings) / sizeof(findings[0])
    );
    for (i = 0; i < finding_count; ++i) {
        rc = cmaper_security_append_finding(
            artifacts,
            &findings[i],
            has_service_context,
            input->protocol,
            input->port
        );
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    surface_count = cmaper_security_detect_management_surfaces_from_http_title(
        input,
        surfaces,
        sizeof(surfaces) / sizeof(surfaces[0])
    );
    for (i = 0; i < surface_count; ++i) {
        rc = cmaper_security_append_surface(
            artifacts,
            &surfaces[i],
            has_service_context,
            input->protocol,
            input->port
        );
        if (rc != CMAPER_OK) {
            return rc;
        }
    }

    return CMAPER_OK;
}

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

        rc = cmaper_security_extract_from_script(out_artifacts, &input, false);
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
            rc = cmaper_security_append_surface(
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

            rc = cmaper_security_extract_from_script(out_artifacts, &input, true);
            if (rc != CMAPER_OK) {
                cmaper_security_host_artifacts_dispose(out_artifacts);
                return rc;
            }
        }
    }

    return CMAPER_OK;
}
