#include "cmaper/security/extract.h"

void cmaper_security_script_input_init(cmaper_security_script_input_t *input) {
    if (input == NULL) {
        return;
    }

    input->script_id = NULL;
    input->output = NULL;
    input->protocol = NULL;
    input->port = 0;
    input->service_name = NULL;
}

void cmaper_security_fingerprint_init(cmaper_security_fingerprint_t *fingerprint) {
    if (fingerprint == NULL) {
        return;
    }

    fingerprint->kind = CMAPER_SECURITY_FP_TLS;
    fingerprint->value[0] = '\0';
    fingerprint->source_script[0] = '\0';
}

void cmaper_security_finding_init(cmaper_security_finding_t *finding) {
    if (finding == NULL) {
        return;
    }

    finding->key[0] = '\0';
    finding->severity = CMAPER_SECURITY_SEVERITY_UNKNOWN;
    finding->state = CMAPER_SECURITY_FINDING_STATE_UNKNOWN;
    finding->title[0] = '\0';
    finding->detail[0] = '\0';
    finding->source_script[0] = '\0';
}

void cmaper_security_management_surface_init(cmaper_security_management_surface_t *surface) {
    if (surface == NULL) {
        return;
    }

    surface->type[0] = '\0';
    surface->detail[0] = '\0';
}

void cmaper_security_aggregate_init(cmaper_security_aggregate_t *aggregate) {
    if (aggregate == NULL) {
        return;
    }

    aggregate->tls_fingerprints = 0;
    aggregate->ssh_fingerprints = 0;
    aggregate->http_fingerprints = 0;
    aggregate->smb_fingerprints = 0;
    aggregate->findings_total = 0;
    aggregate->findings_open = 0;
    aggregate->findings_high_or_worse = 0;
    aggregate->management_surfaces = 0;
}

const char *cmaper_security_fingerprint_kind_name(cmaper_security_fingerprint_kind_t kind) {
    switch (kind) {
    case CMAPER_SECURITY_FP_TLS:
        return "tls";
    case CMAPER_SECURITY_FP_SSH:
        return "ssh";
    case CMAPER_SECURITY_FP_HTTP:
        return "http";
    case CMAPER_SECURITY_FP_SMB:
        return "smb";
    }

    return "unknown";
}

const char *cmaper_security_severity_name(cmaper_security_severity_t severity) {
    switch (severity) {
    case CMAPER_SECURITY_SEVERITY_UNKNOWN:
        return "unknown";
    case CMAPER_SECURITY_SEVERITY_INFO:
        return "info";
    case CMAPER_SECURITY_SEVERITY_LOW:
        return "low";
    case CMAPER_SECURITY_SEVERITY_MEDIUM:
        return "medium";
    case CMAPER_SECURITY_SEVERITY_HIGH:
        return "high";
    case CMAPER_SECURITY_SEVERITY_CRITICAL:
        return "critical";
    }

    return "unknown";
}

const char *cmaper_security_finding_state_name(cmaper_security_finding_state_t state) {
    switch (state) {
    case CMAPER_SECURITY_FINDING_STATE_UNKNOWN:
        return "unknown";
    case CMAPER_SECURITY_FINDING_STATE_OPEN:
        return "open";
    case CMAPER_SECURITY_FINDING_STATE_RESOLVED:
        return "resolved";
    }

    return "unknown";
}

void cmaper_security_aggregate_add_fingerprint(
    cmaper_security_aggregate_t *aggregate,
    const cmaper_security_fingerprint_t *fingerprint
) {
    if (aggregate == NULL || fingerprint == NULL) {
        return;
    }

    switch (fingerprint->kind) {
    case CMAPER_SECURITY_FP_TLS:
        aggregate->tls_fingerprints += 1U;
        break;
    case CMAPER_SECURITY_FP_SSH:
        aggregate->ssh_fingerprints += 1U;
        break;
    case CMAPER_SECURITY_FP_HTTP:
        aggregate->http_fingerprints += 1U;
        break;
    case CMAPER_SECURITY_FP_SMB:
        aggregate->smb_fingerprints += 1U;
        break;
    }
}

void cmaper_security_aggregate_add_finding(
    cmaper_security_aggregate_t *aggregate,
    const cmaper_security_finding_t *finding
) {
    if (aggregate == NULL || finding == NULL) {
        return;
    }

    aggregate->findings_total += 1U;
    if (finding->state == CMAPER_SECURITY_FINDING_STATE_OPEN) {
        aggregate->findings_open += 1U;
    }
    if (finding->severity == CMAPER_SECURITY_SEVERITY_HIGH
        || finding->severity == CMAPER_SECURITY_SEVERITY_CRITICAL) {
        aggregate->findings_high_or_worse += 1U;
    }
}

void cmaper_security_aggregate_add_surface(
    cmaper_security_aggregate_t *aggregate,
    const cmaper_security_management_surface_t *surface
) {
    (void) surface;
    if (aggregate == NULL) {
        return;
    }

    aggregate->management_surfaces += 1U;
}
