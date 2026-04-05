#include "cmaper/security/extract.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    int port;
    const char *type;
    const char *detail;
} cmaper_security_well_known_surface_t;

static const cmaper_security_well_known_surface_t CMAPER_SECURITY_WELL_KNOWN_SURFACES[] = {
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
    {2376, "docker-api-tls", "Docker TLS API management surface"}
};

static int cmaper_security_ascii_tolower(int ch) {
    if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A' + 'a';
    }
    return ch;
}

static void cmaper_security_copy_string(char *out, size_t out_cap, const char *value) {
    if (out == NULL || out_cap == 0) {
        return;
    }

    out[0] = '\0';
    if (value == NULL) {
        return;
    }

    snprintf(out, out_cap, "%s", value);
}

static bool cmaper_security_char_eq_ci(char left, char right) {
    return cmaper_security_ascii_tolower((unsigned char) left)
        == cmaper_security_ascii_tolower((unsigned char) right);
}

static bool cmaper_security_starts_with_ci(const char *value, const char *prefix) {
    size_t i;

    if (value == NULL || prefix == NULL) {
        return false;
    }

    for (i = 0; prefix[i] != '\0'; ++i) {
        if (value[i] == '\0') {
            return false;
        }
        if (!cmaper_security_char_eq_ci(value[i], prefix[i])) {
            return false;
        }
    }
    return true;
}

static bool cmaper_security_contains_ci(const char *haystack, const char *needle) {
    size_t i;
    size_t needle_len;

    if (haystack == NULL || needle == NULL || needle[0] == '\0') {
        return false;
    }

    needle_len = strlen(needle);
    for (i = 0; haystack[i] != '\0'; ++i) {
        size_t j;
        bool match = true;

        for (j = 0; j < needle_len; ++j) {
            if (haystack[i + j] == '\0' || !cmaper_security_char_eq_ci(haystack[i + j], needle[j])) {
                match = false;
                break;
            }
        }

        if (match) {
            return true;
        }
    }

    return false;
}

static bool cmaper_security_token_is_boundary(char ch) {
    return ch == '\0'
        || isspace((unsigned char) ch)
        || ch == ','
        || ch == ';'
        || ch == ')'
        || ch == '('
        || ch == ']'
        || ch == '['
        || ch == '|'
        || ch == '"'
        || ch == '\'';
}

static size_t cmaper_security_normalize_spaces(
    const char *input,
    char *out,
    size_t out_cap,
    bool lower_case
) {
    size_t i = 0;
    size_t out_len = 0;
    bool saw_space = false;

    if (out == NULL || out_cap == 0) {
        return 0;
    }

    if (input == NULL) {
        out[0] = '\0';
        return 0;
    }

    while (input[i] != '\0' && isspace((unsigned char) input[i])) {
        i += 1U;
    }

    for (; input[i] != '\0'; ++i) {
        unsigned char ch = (unsigned char) input[i];
        if (isspace(ch)) {
            saw_space = true;
            continue;
        }

        if (saw_space && out_len + 1U < out_cap && out_len > 0) {
            out[out_len++] = ' ';
        }
        saw_space = false;

        if (out_len + 1U >= out_cap) {
            break;
        }
        out[out_len++] = (char) (lower_case ? cmaper_security_ascii_tolower(ch) : ch);
    }

    while (out_len > 0 && out[out_len - 1U] == ' ') {
        out_len -= 1U;
    }
    out[out_len] = '\0';
    return out_len;
}

static bool cmaper_security_extract_labeled_value(
    const char *text,
    const char *label,
    char *out,
    size_t out_cap
) {
    size_t i;
    size_t label_len;

    if (text == NULL || label == NULL || out == NULL || out_cap == 0) {
        return false;
    }

    out[0] = '\0';
    label_len = strlen(label);
    if (label_len == 0) {
        return false;
    }

    for (i = 0; text[i] != '\0'; ++i) {
        size_t j;
        size_t start;
        size_t out_len = 0;
        bool matches = true;

        for (j = 0; j < label_len; ++j) {
            if (text[i + j] == '\0' || !cmaper_security_char_eq_ci(text[i + j], label[j])) {
                matches = false;
                break;
            }
        }
        if (!matches) {
            continue;
        }

        start = i + label_len;
        while (text[start] != '\0' && isspace((unsigned char) text[start])) {
            start += 1U;
        }
        if (text[start] == ':') {
            start += 1U;
        }
        while (text[start] != '\0' && isspace((unsigned char) text[start])) {
            start += 1U;
        }
        while (text[start] != '\0' && !cmaper_security_token_is_boundary(text[start])) {
            if (out_len + 1U >= out_cap) {
                break;
            }
            out[out_len++] = (char) cmaper_security_ascii_tolower((unsigned char) text[start]);
            start += 1U;
        }
        out[out_len] = '\0';
        if (out_len > 0) {
            return true;
        }
    }

    return false;
}

static bool cmaper_security_extract_hex_colon_token(
    const char *text,
    char *out,
    size_t out_cap
) {
    size_t i;

    if (text == NULL || out == NULL || out_cap == 0) {
        return false;
    }
    out[0] = '\0';

    for (i = 0; text[i] != '\0'; ++i) {
        size_t j = i;
        size_t len = 0;
        size_t colon_count = 0;

        while (text[j] != '\0' && !isspace((unsigned char) text[j])) {
            unsigned char ch = (unsigned char) text[j];
            if (!(isxdigit(ch) || ch == ':')) {
                break;
            }
            if (ch == ':') {
                colon_count += 1U;
            }
            len += 1U;
            j += 1U;
        }

        if (len >= 17U && colon_count >= 5U && len + 1U < out_cap) {
            size_t k;
            for (k = 0; k < len; ++k) {
                out[k] = (char) cmaper_security_ascii_tolower((unsigned char) text[i + k]);
            }
            out[len] = '\0';
            return true;
        }
    }

    return false;
}

static bool cmaper_security_extract_line_value_ci(
    const char *text,
    const char *label,
    char *out,
    size_t out_cap
) {
    size_t label_len;
    size_t i;

    if (text == NULL || label == NULL || out == NULL || out_cap == 0) {
        return false;
    }
    out[0] = '\0';
    label_len = strlen(label);
    if (label_len == 0) {
        return false;
    }

    for (i = 0; text[i] != '\0'; ++i) {
        size_t j;
        bool matches = true;
        size_t line_start = i;
        size_t value_start;
        size_t out_len = 0;

        if (line_start > 0 && text[line_start - 1U] != '\n' && text[line_start - 1U] != '\r') {
            continue;
        }

        for (j = 0; j < label_len; ++j) {
            if (text[line_start + j] == '\0'
                || !cmaper_security_char_eq_ci(text[line_start + j], label[j])) {
                matches = false;
                break;
            }
        }
        if (!matches) {
            continue;
        }

        value_start = line_start + label_len;
        while (text[value_start] != '\0' && isspace((unsigned char) text[value_start])) {
            value_start += 1U;
        }
        if (text[value_start] == ':') {
            value_start += 1U;
        }
        while (text[value_start] != '\0' && isspace((unsigned char) text[value_start])) {
            value_start += 1U;
        }

        while (text[value_start] != '\0'
            && text[value_start] != '\n'
            && text[value_start] != '\r') {
            if (out_len + 1U >= out_cap) {
                break;
            }
            out[out_len++] = text[value_start++];
        }
        out[out_len] = '\0';
        cmaper_security_normalize_spaces(out, out, out_cap, true);
        return out[0] != '\0';
    }

    return false;
}

static bool cmaper_security_extract_first_text_line(const char *text, char *out, size_t out_cap) {
    size_t i = 0;
    size_t out_len = 0;

    if (text == NULL || out == NULL || out_cap == 0) {
        return false;
    }
    out[0] = '\0';

    while (text[i] != '\0') {
        if (text[i] == '\n' || text[i] == '\r') {
            i += 1U;
            continue;
        }
        if (isspace((unsigned char) text[i])) {
            i += 1U;
            continue;
        }
        break;
    }

    while (text[i] != '\0' && text[i] != '\n' && text[i] != '\r') {
        if (out_len + 1U >= out_cap) {
            break;
        }
        out[out_len++] = text[i++];
    }
    out[out_len] = '\0';
    cmaper_security_normalize_spaces(out, out, out_cap, false);
    return out[0] != '\0';
}

static bool cmaper_security_script_is_tls(const char *script_id) {
    if (script_id == NULL) {
        return false;
    }

    return cmaper_security_starts_with_ci(script_id, "ssl-")
        || cmaper_security_starts_with_ci(script_id, "tls-")
        || cmaper_security_contains_ci(script_id, "https-cert");
}

static bool cmaper_security_script_is_ssh(const char *script_id) {
    if (script_id == NULL) {
        return false;
    }

    return cmaper_security_starts_with_ci(script_id, "ssh-")
        || cmaper_security_starts_with_ci(script_id, "ssh2-");
}

static bool cmaper_security_script_is_http(const char *script_id) {
    if (script_id == NULL) {
        return false;
    }

    return cmaper_security_starts_with_ci(script_id, "http-")
        || cmaper_security_starts_with_ci(script_id, "https-")
        || cmaper_security_contains_ci(script_id, "http");
}

static bool cmaper_security_script_is_smb(const char *script_id) {
    if (script_id == NULL) {
        return false;
    }

    return cmaper_security_starts_with_ci(script_id, "smb-")
        || cmaper_security_starts_with_ci(script_id, "smb2-")
        || cmaper_security_contains_ci(script_id, "nbstat");
}

static void cmaper_security_set_script_source(
    const cmaper_security_script_input_t *input,
    char *out_script,
    size_t out_cap
) {
    if (out_script == NULL || out_cap == 0) {
        return;
    }
    out_script[0] = '\0';
    if (input == NULL || input->script_id == NULL) {
        return;
    }
    cmaper_security_copy_string(out_script, out_cap, input->script_id);
}

static bool cmaper_security_is_security_signal(const char *script_id, const char *output) {
    if (cmaper_security_contains_ci(output, "cve-")
        || cmaper_security_contains_ci(output, "cwe-")
        || cmaper_security_contains_ci(output, "ghsa-")
        || cmaper_security_contains_ci(output, "vulnerable")
        || cmaper_security_contains_ci(output, "exploit")
        || cmaper_security_contains_ci(output, "exposed")
        || cmaper_security_contains_ci(output, "security issue")
        || cmaper_security_contains_ci(output, "risk")) {
        return true;
    }

    return cmaper_security_contains_ci(script_id, "vuln")
        || cmaper_security_contains_ci(script_id, "vulner")
        || cmaper_security_contains_ci(script_id, "security")
        || cmaper_security_contains_ci(script_id, "heartbleed")
        || cmaper_security_contains_ci(script_id, "auth-bypass");
}

static cmaper_security_severity_t cmaper_security_infer_severity(
    const char *script_id,
    const char *output
) {
    if (cmaper_security_contains_ci(output, "critical")) {
        return CMAPER_SECURITY_SEVERITY_CRITICAL;
    }
    if (cmaper_security_contains_ci(output, "high")) {
        return CMAPER_SECURITY_SEVERITY_HIGH;
    }
    if (cmaper_security_contains_ci(output, "medium")
        || cmaper_security_contains_ci(output, "moderate")) {
        return CMAPER_SECURITY_SEVERITY_MEDIUM;
    }
    if (cmaper_security_contains_ci(output, "low")) {
        return CMAPER_SECURITY_SEVERITY_LOW;
    }
    if (cmaper_security_contains_ci(output, "informational")
        || cmaper_security_contains_ci(output, "info")) {
        return CMAPER_SECURITY_SEVERITY_INFO;
    }
    if (cmaper_security_contains_ci(output, "cve-")
        || cmaper_security_contains_ci(script_id, "vuln")
        || cmaper_security_contains_ci(output, "vulnerable")) {
        return CMAPER_SECURITY_SEVERITY_MEDIUM;
    }

    return CMAPER_SECURITY_SEVERITY_UNKNOWN;
}

static cmaper_security_finding_state_t cmaper_security_infer_state(const char *output) {
    if (cmaper_security_contains_ci(output, "not vulnerable")
        || cmaper_security_contains_ci(output, "patched")
        || cmaper_security_contains_ci(output, "fixed")
        || cmaper_security_contains_ci(output, "mitigated")) {
        return CMAPER_SECURITY_FINDING_STATE_RESOLVED;
    }

    if (cmaper_security_contains_ci(output, "vulnerable")
        || cmaper_security_contains_ci(output, "exposed")
        || cmaper_security_contains_ci(output, "open")
        || cmaper_security_contains_ci(output, "affected")) {
        return CMAPER_SECURITY_FINDING_STATE_OPEN;
    }

    return CMAPER_SECURITY_FINDING_STATE_UNKNOWN;
}

static bool cmaper_security_identifier_exists(
    const char identifiers[][CMAPER_SECURITY_FINDING_KEY_CAP],
    size_t count,
    const char *candidate
) {
    size_t i;
    for (i = 0; i < count; ++i) {
        if (strcmp(identifiers[i], candidate) == 0) {
            return true;
        }
    }
    return false;
}

static void cmaper_security_collect_identifier(
    const char *start,
    size_t max_len,
    char *out,
    size_t out_cap
) {
    size_t i = 0;
    if (out == NULL || out_cap == 0) {
        return;
    }
    out[0] = '\0';
    while (i < max_len && start[i] != '\0' && !cmaper_security_token_is_boundary(start[i])) {
        if (i + 1U >= out_cap) {
            break;
        }
        out[i] = (char) toupper((unsigned char) start[i]);
        i += 1U;
    }
    out[i] = '\0';
}

static size_t cmaper_security_collect_identifiers(
    const char *text,
    char identifiers[][CMAPER_SECURITY_FINDING_KEY_CAP],
    size_t id_cap
) {
    size_t i;
    size_t count = 0;

    if (text == NULL || identifiers == NULL || id_cap == 0) {
        return 0;
    }

    for (i = 0; text[i] != '\0'; ++i) {
        char candidate[CMAPER_SECURITY_FINDING_KEY_CAP];

        if (count >= id_cap) {
            break;
        }

        candidate[0] = '\0';
        if (cmaper_security_starts_with_ci(&text[i], "CVE-")) {
            cmaper_security_collect_identifier(&text[i], 32U, candidate, sizeof(candidate));
        } else if (cmaper_security_starts_with_ci(&text[i], "CWE-")) {
            cmaper_security_collect_identifier(&text[i], 24U, candidate, sizeof(candidate));
        } else if (cmaper_security_starts_with_ci(&text[i], "GHSA-")) {
            cmaper_security_collect_identifier(&text[i], 32U, candidate, sizeof(candidate));
        } else {
            continue;
        }

        if (candidate[0] == '\0') {
            continue;
        }
        if (cmaper_security_identifier_exists(identifiers, count, candidate)) {
            continue;
        }

        cmaper_security_copy_string(identifiers[count], CMAPER_SECURITY_FINDING_KEY_CAP, candidate);
        count += 1U;
    }

    return count;
}

static void cmaper_security_humanize_script_id(
    const char *script_id,
    char *out,
    size_t out_cap
) {
    size_t in_index = 0;
    size_t out_index = 0;
    bool new_word = true;

    if (out == NULL || out_cap == 0) {
        return;
    }
    out[0] = '\0';

    if (script_id == NULL || script_id[0] == '\0') {
        cmaper_security_copy_string(out, out_cap, "Script output");
        return;
    }

    while (script_id[in_index] != '\0' && out_index + 1U < out_cap) {
        unsigned char ch = (unsigned char) script_id[in_index++];
        if (ch == '-' || ch == '_' || ch == '/' || ch == '.') {
            if (out_index > 0 && out[out_index - 1U] != ' ' && out_index + 1U < out_cap) {
                out[out_index++] = ' ';
            }
            new_word = true;
            continue;
        }

        if (new_word) {
            out[out_index++] = (char) toupper(ch);
            new_word = false;
        } else {
            out[out_index++] = (char) ch;
        }
    }
    out[out_index] = '\0';
}

static void cmaper_security_make_title(
    const char *key,
    const char *script_id,
    char *out,
    size_t out_cap
) {
    char script_title[CMAPER_SECURITY_FINDING_TITLE_CAP];

    if (out == NULL || out_cap == 0) {
        return;
    }
    out[0] = '\0';

    if (key != NULL && cmaper_security_starts_with_ci(key, "CVE-")) {
        snprintf(out, out_cap, "Vulnerability %s", key);
        return;
    }
    if (key != NULL && cmaper_security_starts_with_ci(key, "GHSA-")) {
        snprintf(out, out_cap, "Security advisory %s", key);
        return;
    }
    if (key != NULL && cmaper_security_starts_with_ci(key, "CWE-")) {
        snprintf(out, out_cap, "Weakness %s", key);
        return;
    }

    cmaper_security_humanize_script_id(script_id, script_title, sizeof(script_title));
    snprintf(out, out_cap, "Potential issue from %s", script_title);
}

static bool cmaper_security_append_surface(
    cmaper_security_management_surface_t *out_items,
    size_t out_cap,
    size_t *in_out_count,
    const char *type,
    const char *detail
) {
    size_t i;

    if (out_items == NULL || in_out_count == NULL || type == NULL || detail == NULL) {
        return false;
    }

    for (i = 0; i < *in_out_count; ++i) {
        if (strcmp(out_items[i].type, type) == 0 && strcmp(out_items[i].detail, detail) == 0) {
            return true;
        }
    }

    if (*in_out_count >= out_cap) {
        return false;
    }

    cmaper_security_management_surface_init(&out_items[*in_out_count]);
    cmaper_security_copy_string(
        out_items[*in_out_count].type,
        sizeof(out_items[*in_out_count].type),
        type
    );
    cmaper_security_copy_string(
        out_items[*in_out_count].detail,
        sizeof(out_items[*in_out_count].detail),
        detail
    );
    *in_out_count += 1U;
    return true;
}

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

size_t cmaper_security_extract_findings(
    const cmaper_security_script_input_t *input,
    cmaper_security_finding_t *out_items,
    size_t out_cap
) {
    char identifiers[8][CMAPER_SECURITY_FINDING_KEY_CAP];
    size_t identifier_count;
    size_t i;
    char normalized_detail[CMAPER_SECURITY_FINDING_DETAIL_CAP];
    cmaper_security_severity_t severity;
    cmaper_security_finding_state_t state;

    if (input == NULL || out_items == NULL || out_cap == 0) {
        return 0;
    }
    if (input->script_id == NULL || input->output == NULL) {
        return 0;
    }

    identifier_count = cmaper_security_collect_identifiers(
        input->output,
        identifiers,
        sizeof(identifiers) / sizeof(identifiers[0])
    );

    if (identifier_count == 0 && !cmaper_security_is_security_signal(input->script_id, input->output)) {
        return 0;
    }

    cmaper_security_normalize_spaces(
        input->output,
        normalized_detail,
        sizeof(normalized_detail),
        false
    );

    severity = cmaper_security_infer_severity(input->script_id, input->output);
    state = cmaper_security_infer_state(input->output);

    if (identifier_count == 0) {
        identifier_count = 1;
        snprintf(identifiers[0], sizeof(identifiers[0]), "script:%s", input->script_id);
    }

    if (identifier_count > out_cap) {
        identifier_count = out_cap;
    }

    for (i = 0; i < identifier_count; ++i) {
        cmaper_security_finding_init(&out_items[i]);
        cmaper_security_copy_string(out_items[i].key, sizeof(out_items[i].key), identifiers[i]);
        out_items[i].severity = severity;
        out_items[i].state = state;
        cmaper_security_make_title(
            out_items[i].key,
            input->script_id,
            out_items[i].title,
            sizeof(out_items[i].title)
        );
        cmaper_security_copy_string(
            out_items[i].detail,
            sizeof(out_items[i].detail),
            normalized_detail[0] != '\0' ? normalized_detail : input->output
        );
        cmaper_security_set_script_source(input, out_items[i].source_script, sizeof(out_items[i].source_script));
    }

    return identifier_count;
}

size_t cmaper_security_detect_management_surfaces_for_port(
    const char *protocol,
    int port,
    const char *service_name,
    cmaper_security_management_surface_t *out_items,
    size_t out_cap
) {
    size_t i;
    size_t count = 0;

    if (out_items == NULL || out_cap == 0 || port <= 0) {
        return 0;
    }

    if (protocol != NULL && protocol[0] != '\0') {
        if (!cmaper_security_starts_with_ci(protocol, "tcp")
            && !cmaper_security_starts_with_ci(protocol, "udp")) {
            return 0;
        }
    }

    for (i = 0; i < sizeof(CMAPER_SECURITY_WELL_KNOWN_SURFACES)
            / sizeof(CMAPER_SECURITY_WELL_KNOWN_SURFACES[0]); ++i) {
        if (CMAPER_SECURITY_WELL_KNOWN_SURFACES[i].port != port) {
            continue;
        }
        (void) cmaper_security_append_surface(
            out_items,
            out_cap,
            &count,
            CMAPER_SECURITY_WELL_KNOWN_SURFACES[i].type,
            CMAPER_SECURITY_WELL_KNOWN_SURFACES[i].detail
        );
    }

    if (service_name != NULL && service_name[0] != '\0') {
        if (cmaper_security_contains_ci(service_name, "http")
            && port != 80
            && port != 443
            && port != 8080
            && port != 8443) {
            (void) cmaper_security_append_surface(
                out_items,
                out_cap,
                &count,
                "web-http",
                "HTTP service-detected management/web surface"
            );
        }
        if (cmaper_security_contains_ci(service_name, "https")
            && port != 443
            && port != 8443) {
            (void) cmaper_security_append_surface(
                out_items,
                out_cap,
                &count,
                "web-https",
                "HTTPS service-detected management/web surface"
            );
        }
    }

    return count;
}

size_t cmaper_security_detect_management_surfaces_from_http_title(
    const cmaper_security_script_input_t *input,
    cmaper_security_management_surface_t *out_items,
    size_t out_cap
) {
    static const char *KEYWORDS[] = {
        "login",
        "admin",
        "dashboard",
        "management",
        "panel",
        "console",
        "webmin",
        "router",
        "camera",
        "drac",
        "ilo",
        "ipmi",
        "grafana",
        "kibana"
    };
    char title[CMAPER_SECURITY_SURFACE_DETAIL_CAP];
    char normalized[CMAPER_SECURITY_SURFACE_DETAIL_CAP];
    size_t i;
    size_t count = 0;
    const char *surface_type = "web-admin-http";

    if (input == NULL || input->output == NULL || out_items == NULL || out_cap == 0) {
        return 0;
    }
    if (input->script_id == NULL || !cmaper_security_contains_ci(input->script_id, "http-title")) {
        return 0;
    }
    if (!cmaper_security_extract_first_text_line(input->output, title, sizeof(title))) {
        return 0;
    }

    cmaper_security_normalize_spaces(title, normalized, sizeof(normalized), true);
    if (normalized[0] == '\0') {
        return 0;
    }

    if ((input->port == 443 || input->port == 8443)
        || cmaper_security_contains_ci(input->service_name, "https")) {
        surface_type = "web-admin-https";
    }

    for (i = 0; i < sizeof(KEYWORDS) / sizeof(KEYWORDS[0]); ++i) {
        if (!cmaper_security_contains_ci(normalized, KEYWORDS[i])) {
            continue;
        }

        {
            char detail[CMAPER_SECURITY_SURFACE_DETAIL_CAP];
            snprintf(detail, sizeof(detail), "HTTP title hint: %s", title);
            (void) cmaper_security_append_surface(
                out_items,
                out_cap,
                &count,
                surface_type,
                detail
            );
        }
        break;
    }

    return count;
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
