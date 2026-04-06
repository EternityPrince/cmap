#include "cmaper/security/internal/nmap_extract_internal.h"

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

cmaper_err_t cmaper_security_nmap_append_fingerprint(
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

cmaper_err_t cmaper_security_nmap_append_finding(
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

cmaper_err_t cmaper_security_nmap_append_surface(
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
