#include "cmaper/history/fuzzy.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static int cmaper_history_ascii_tolower(int ch) {
    if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A' + 'a';
    }
    return ch;
}

static bool cmaper_history_token_boundary(char ch) {
    return ch == '\0'
        || isspace((unsigned char) ch)
        || ch == '_'
        || ch == '-'
        || ch == ':'
        || ch == '.'
        || ch == ','
        || ch == ';'
        || ch == '/'
        || ch == '\\';
}

static int cmaper_history_ip_family(const char *ip) {
    struct in_addr v4;
    struct in6_addr v6;

    if (ip == NULL || ip[0] == '\0') {
        return 0;
    }

    if (inet_pton(AF_INET, ip, &v4) == 1) {
        return AF_INET;
    }
    if (inet_pton(AF_INET6, ip, &v6) == 1) {
        return AF_INET6;
    }

    return 0;
}

void cmaper_history_normalize_token(const char *value, char *out, size_t out_cap) {
    size_t i = 0;
    size_t out_len = 0;
    bool want_space = false;

    if (out == NULL || out_cap == 0) {
        return;
    }

    out[0] = '\0';
    if (value == NULL) {
        return;
    }

    while (value[i] != '\0' && isspace((unsigned char) value[i])) {
        i += 1U;
    }

    while (value[i] != '\0') {
        unsigned char ch = (unsigned char) value[i];
        if (isspace(ch)) {
            want_space = out_len > 0;
            i += 1U;
            continue;
        }

        if (want_space) {
            if (out_len + 1U >= out_cap) {
                break;
            }
            out[out_len++] = ' ';
            want_space = false;
        }

        if (out_len + 1U >= out_cap) {
            break;
        }
        out[out_len++] = (char) cmaper_history_ascii_tolower(ch);
        i += 1U;
    }

    while (out_len > 0 && out[out_len - 1U] == ' ') {
        out_len -= 1U;
    }
    out[out_len] = '\0';
}

void cmaper_history_normalize_mac(const char *value, char *out, size_t out_cap) {
    size_t i;
    size_t out_len = 0;

    if (out == NULL || out_cap == 0) {
        return;
    }

    out[0] = '\0';
    if (value == NULL) {
        return;
    }

    for (i = 0; value[i] != '\0'; ++i) {
        unsigned char ch = (unsigned char) value[i];
        if (ch == '-') {
            ch = ':';
        }
        if (isspace(ch)) {
            continue;
        }
        if (out_len + 1U >= out_cap) {
            break;
        }
        out[out_len++] = (char) toupper(ch);
    }

    out[out_len] = '\0';
}

void cmaper_history_make_fuzzy_key(const char *value, char *out, size_t out_cap) {
    size_t i;
    size_t out_len = 0;
    bool in_boundary = true;

    if (out == NULL || out_cap == 0) {
        return;
    }

    out[0] = '\0';
    if (value == NULL) {
        return;
    }

    for (i = 0; value[i] != '\0'; ++i) {
        char ch = value[i];
        if (cmaper_history_token_boundary(ch)) {
            in_boundary = true;
            continue;
        }

        if (out_len + 1U >= out_cap) {
            break;
        }

        if (in_boundary && out_len > 0) {
            out[out_len++] = '|';
            if (out_len + 1U >= out_cap) {
                break;
            }
        }

        out[out_len++] = (char) cmaper_history_ascii_tolower((unsigned char) ch);
        in_boundary = false;
    }

    out[out_len] = '\0';
}

bool cmaper_history_fuzzy_equal(const char *left, const char *right) {
    char left_norm[CMAPER_HISTORY_DETAIL_CAP];
    char right_norm[CMAPER_HISTORY_DETAIL_CAP];

    if (left == NULL || right == NULL) {
        return left == right;
    }

    cmaper_history_make_fuzzy_key(left, left_norm, sizeof(left_norm));
    cmaper_history_make_fuzzy_key(right, right_norm, sizeof(right_norm));

    return strcmp(left_norm, right_norm) == 0;
}

bool cmaper_history_fuzzy_contains(const char *haystack, const char *needle) {
    char normalized_haystack[CMAPER_HISTORY_DETAIL_CAP];
    char normalized_needle[CMAPER_HISTORY_DETAIL_CAP];

    if (haystack == NULL || needle == NULL || needle[0] == '\0') {
        return false;
    }

    cmaper_history_make_fuzzy_key(haystack, normalized_haystack, sizeof(normalized_haystack));
    cmaper_history_make_fuzzy_key(needle, normalized_needle, sizeof(normalized_needle));
    if (normalized_needle[0] == '\0') {
        return false;
    }

    return strstr(normalized_haystack, normalized_needle) != NULL;
}

int cmaper_history_compare_ip(const char *left, const char *right) {
    int left_family;
    int right_family;

    if (left == NULL && right == NULL) {
        return 0;
    }
    if (left == NULL) {
        return -1;
    }
    if (right == NULL) {
        return 1;
    }

    left_family = cmaper_history_ip_family(left);
    right_family = cmaper_history_ip_family(right);
    if (left_family != right_family) {
        if (left_family == AF_INET) {
            return -1;
        }
        if (right_family == AF_INET) {
            return 1;
        }
        if (left_family == AF_INET6) {
            return -1;
        }
        if (right_family == AF_INET6) {
            return 1;
        }
        return strcmp(left, right);
    }

    if (left_family == AF_INET) {
        struct in_addr left_addr;
        struct in_addr right_addr;

        if (inet_pton(AF_INET, left, &left_addr) == 1
            && inet_pton(AF_INET, right, &right_addr) == 1) {
            return memcmp(&left_addr, &right_addr, sizeof(left_addr));
        }
    } else if (left_family == AF_INET6) {
        struct in6_addr left_addr6;
        struct in6_addr right_addr6;

        if (inet_pton(AF_INET6, left, &left_addr6) == 1
            && inet_pton(AF_INET6, right, &right_addr6) == 1) {
            return memcmp(&left_addr6, &right_addr6, sizeof(left_addr6));
        }
    }

    return strcmp(left, right);
}

int cmaper_history_compare_ids(const char *left, const char *right) {
    if (left == NULL && right == NULL) {
        return 0;
    }
    if (left == NULL) {
        return -1;
    }
    if (right == NULL) {
        return 1;
    }

    return strcmp(left, right);
}
