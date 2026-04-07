#ifndef CMAPER_SECURITY_INTERNAL_EXTRACT_INTERNAL_H
#define CMAPER_SECURITY_INTERNAL_EXTRACT_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>

#include "cmaper/security/extract.h"

void cmaper_security_copy_string(char *out, size_t out_cap, const char *value);

bool cmaper_security_starts_with_ci(const char *value, const char *prefix);
bool cmaper_security_contains_ci(const char *haystack, const char *needle);
bool cmaper_security_token_is_boundary(char ch);

size_t cmaper_security_normalize_spaces(const char *input, char *out,
                                        size_t out_cap, bool lower_case);

bool cmaper_security_extract_labeled_value(const char *text, const char *label,
                                           char *out, size_t out_cap);

bool cmaper_security_extract_hex_colon_token(const char *text, char *out,
                                             size_t out_cap);

bool cmaper_security_extract_line_value_ci(const char *text, const char *label,
                                           char *out, size_t out_cap);

bool cmaper_security_extract_first_text_line(const char *text, char *out,
                                             size_t out_cap);

bool cmaper_security_script_is_tls(const char *script_id);
bool cmaper_security_script_is_ssh(const char *script_id);
bool cmaper_security_script_is_http(const char *script_id);
bool cmaper_security_script_is_smb(const char *script_id);

void cmaper_security_set_script_source(
    const cmaper_security_script_input_t *input, char *out_script,
    size_t out_cap);

#endif
