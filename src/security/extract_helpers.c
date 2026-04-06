#include "cmaper/security/extract.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "cmaper/security/internal/extract_internal.h"

static int cmaper_security_ascii_tolower(int ch) {
    if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A' + 'a';
    }
    return ch;
}

void cmaper_security_copy_string(char *out, size_t out_cap, const char *value) {
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

bool cmaper_security_starts_with_ci(const char *value, const char *prefix) {
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

bool cmaper_security_contains_ci(const char *haystack, const char *needle) {
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

bool cmaper_security_token_is_boundary(char ch) {
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

size_t cmaper_security_normalize_spaces(
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

bool cmaper_security_extract_labeled_value(
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

bool cmaper_security_extract_hex_colon_token(
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

bool cmaper_security_extract_line_value_ci(
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

bool cmaper_security_extract_first_text_line(const char *text, char *out, size_t out_cap) {
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

bool cmaper_security_script_is_tls(const char *script_id) {
    if (script_id == NULL) {
        return false;
    }

    return cmaper_security_starts_with_ci(script_id, "ssl-")
        || cmaper_security_starts_with_ci(script_id, "tls-")
        || cmaper_security_contains_ci(script_id, "https-cert");
}

bool cmaper_security_script_is_ssh(const char *script_id) {
    if (script_id == NULL) {
        return false;
    }

    return cmaper_security_starts_with_ci(script_id, "ssh-")
        || cmaper_security_starts_with_ci(script_id, "ssh2-");
}

bool cmaper_security_script_is_http(const char *script_id) {
    if (script_id == NULL) {
        return false;
    }

    return cmaper_security_starts_with_ci(script_id, "http-")
        || cmaper_security_starts_with_ci(script_id, "https-")
        || cmaper_security_contains_ci(script_id, "http");
}

bool cmaper_security_script_is_smb(const char *script_id) {
    if (script_id == NULL) {
        return false;
    }

    return cmaper_security_starts_with_ci(script_id, "smb-")
        || cmaper_security_starts_with_ci(script_id, "smb2-")
        || cmaper_security_contains_ci(script_id, "nbstat");
}

void cmaper_security_set_script_source(
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
