#include "cmaper/security/extract.h"

#include <stdio.h>
#include <string.h>

#include "cmaper/security/internal/extract_internal.h"

bool cmaper_security_normalize_tls_fingerprint(
    const cmaper_security_script_input_t *input,
    cmaper_security_fingerprint_t *out_fingerprint
) {
    char hash_value[160];
    char subject[128];
    char issuer[128];
    char normalized[CMAPER_SECURITY_FINGERPRINT_VALUE_CAP];

    if (input == NULL || out_fingerprint == NULL || input->output == NULL) {
        return false;
    }
    if (!cmaper_security_script_is_tls(input->script_id)) {
        return false;
    }

    cmaper_security_fingerprint_init(out_fingerprint);
    out_fingerprint->kind = CMAPER_SECURITY_FP_TLS;
    cmaper_security_set_script_source(input, out_fingerprint->source_script, sizeof(out_fingerprint->source_script));

    hash_value[0] = '\0';
    if (cmaper_security_extract_labeled_value(input->output, "sha256", hash_value, sizeof(hash_value))) {
        snprintf(out_fingerprint->value, sizeof(out_fingerprint->value), "sha256:%s", hash_value);
        return true;
    }
    if (cmaper_security_extract_labeled_value(input->output, "sha1", hash_value, sizeof(hash_value))) {
        snprintf(out_fingerprint->value, sizeof(out_fingerprint->value), "sha1:%s", hash_value);
        return true;
    }
    if (cmaper_security_extract_labeled_value(input->output, "md5", hash_value, sizeof(hash_value))) {
        snprintf(out_fingerprint->value, sizeof(out_fingerprint->value), "md5:%s", hash_value);
        return true;
    }

    subject[0] = '\0';
    issuer[0] = '\0';
    (void) cmaper_security_extract_line_value_ci(input->output, "subject", subject, sizeof(subject));
    (void) cmaper_security_extract_line_value_ci(input->output, "issuer", issuer, sizeof(issuer));
    if (subject[0] != '\0' || issuer[0] != '\0') {
        snprintf(
            out_fingerprint->value,
            sizeof(out_fingerprint->value),
            "cert:subject=%s;issuer=%s",
            subject[0] != '\0' ? subject : "-",
            issuer[0] != '\0' ? issuer : "-"
        );
        return true;
    }

    cmaper_security_normalize_spaces(input->output, normalized, sizeof(normalized), true);
    if (normalized[0] == '\0') {
        return false;
    }

    snprintf(out_fingerprint->value, sizeof(out_fingerprint->value), "raw:%s", normalized);
    return true;
}

bool cmaper_security_normalize_ssh_fingerprint(
    const cmaper_security_script_input_t *input,
    cmaper_security_fingerprint_t *out_fingerprint
) {
    char hash_value[160];
    char normalized[CMAPER_SECURITY_FINGERPRINT_VALUE_CAP];

    if (input == NULL || out_fingerprint == NULL || input->output == NULL) {
        return false;
    }
    if (!cmaper_security_script_is_ssh(input->script_id)) {
        return false;
    }

    cmaper_security_fingerprint_init(out_fingerprint);
    out_fingerprint->kind = CMAPER_SECURITY_FP_SSH;
    cmaper_security_set_script_source(input, out_fingerprint->source_script, sizeof(out_fingerprint->source_script));

    hash_value[0] = '\0';
    if (cmaper_security_extract_labeled_value(input->output, "sha256", hash_value, sizeof(hash_value))) {
        snprintf(out_fingerprint->value, sizeof(out_fingerprint->value), "sha256:%s", hash_value);
        return true;
    }
    if (cmaper_security_extract_labeled_value(input->output, "md5", hash_value, sizeof(hash_value))) {
        snprintf(out_fingerprint->value, sizeof(out_fingerprint->value), "md5:%s", hash_value);
        return true;
    }
    if (cmaper_security_extract_hex_colon_token(input->output, hash_value, sizeof(hash_value))) {
        snprintf(out_fingerprint->value, sizeof(out_fingerprint->value), "hex:%s", hash_value);
        return true;
    }

    cmaper_security_normalize_spaces(input->output, normalized, sizeof(normalized), true);
    if (normalized[0] == '\0') {
        return false;
    }

    snprintf(out_fingerprint->value, sizeof(out_fingerprint->value), "raw:%s", normalized);
    return true;
}

bool cmaper_security_normalize_http_fingerprint(
    const cmaper_security_script_input_t *input,
    cmaper_security_fingerprint_t *out_fingerprint
) {
    char normalized[CMAPER_SECURITY_FINGERPRINT_VALUE_CAP];
    char title[CMAPER_SECURITY_SURFACE_DETAIL_CAP];
    char server[CMAPER_SECURITY_SURFACE_DETAIL_CAP];
    char hash[96];

    if (input == NULL || out_fingerprint == NULL || input->output == NULL) {
        return false;
    }
    if (!cmaper_security_script_is_http(input->script_id)) {
        return false;
    }

    cmaper_security_fingerprint_init(out_fingerprint);
    out_fingerprint->kind = CMAPER_SECURITY_FP_HTTP;
    cmaper_security_set_script_source(input, out_fingerprint->source_script, sizeof(out_fingerprint->source_script));

    title[0] = '\0';
    if (cmaper_security_contains_ci(input->script_id, "http-title")
        && cmaper_security_extract_first_text_line(input->output, title, sizeof(title))) {
        cmaper_security_normalize_spaces(title, title, sizeof(title), true);
        if (title[0] != '\0') {
            snprintf(out_fingerprint->value, sizeof(out_fingerprint->value), "title:%s", title);
            return true;
        }
    }

    server[0] = '\0';
    if (cmaper_security_extract_line_value_ci(input->output, "server", server, sizeof(server))) {
        snprintf(out_fingerprint->value, sizeof(out_fingerprint->value), "server:%s", server);
        return true;
    }

    hash[0] = '\0';
    if (cmaper_security_extract_labeled_value(input->output, "md5", hash, sizeof(hash))) {
        snprintf(out_fingerprint->value, sizeof(out_fingerprint->value), "favicon-md5:%s", hash);
        return true;
    }

    cmaper_security_normalize_spaces(input->output, normalized, sizeof(normalized), true);
    if (normalized[0] == '\0') {
        return false;
    }
    snprintf(out_fingerprint->value, sizeof(out_fingerprint->value), "raw:%s", normalized);
    return true;
}
bool cmaper_security_normalize_smb_fingerprint(
    const cmaper_security_script_input_t *input,
    cmaper_security_fingerprint_t *out_fingerprint
) {
    char os_value[80];
    char host_value[80];
    char domain_value[80];
    char signing_value[80];
    char normalized[CMAPER_SECURITY_FINGERPRINT_VALUE_CAP];

    if (input == NULL || out_fingerprint == NULL || input->output == NULL) {
        return false;
    }
    if (!cmaper_security_script_is_smb(input->script_id)) {
        return false;
    }

    cmaper_security_fingerprint_init(out_fingerprint);
    out_fingerprint->kind = CMAPER_SECURITY_FP_SMB;
    cmaper_security_set_script_source(input, out_fingerprint->source_script, sizeof(out_fingerprint->source_script));

    os_value[0] = '\0';
    host_value[0] = '\0';
    domain_value[0] = '\0';
    signing_value[0] = '\0';

    (void) cmaper_security_extract_line_value_ci(input->output, "os", os_value, sizeof(os_value));
    (void) cmaper_security_extract_line_value_ci(input->output, "computer name", host_value, sizeof(host_value));
    (void) cmaper_security_extract_line_value_ci(input->output, "domain name", domain_value, sizeof(domain_value));
    (void) cmaper_security_extract_line_value_ci(input->output, "signing", signing_value, sizeof(signing_value));

    if (os_value[0] != '\0'
        || host_value[0] != '\0'
        || domain_value[0] != '\0'
        || signing_value[0] != '\0') {
        snprintf(
            out_fingerprint->value,
            sizeof(out_fingerprint->value),
            "os=%s;host=%s;domain=%s;signing=%s",
            os_value[0] != '\0' ? os_value : "-",
            host_value[0] != '\0' ? host_value : "-",
            domain_value[0] != '\0' ? domain_value : "-",
            signing_value[0] != '\0' ? signing_value : "-"
        );
        return true;
    }

    cmaper_security_normalize_spaces(input->output, normalized, sizeof(normalized), true);
    if (normalized[0] == '\0') {
        return false;
    }
    snprintf(out_fingerprint->value, sizeof(out_fingerprint->value), "raw:%s", normalized);
    return true;
}
