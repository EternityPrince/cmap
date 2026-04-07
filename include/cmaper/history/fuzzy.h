#ifndef CMAPER_HISTORY_FUZZY_H
#define CMAPER_HISTORY_FUZZY_H

#include <stdbool.h>
#include <stddef.h>

#include "cmaper/history/domain.h"

void cmaper_history_normalize_token(const char *value, char *out,
                                    size_t out_cap);
void cmaper_history_normalize_mac(const char *value, char *out, size_t out_cap);
void cmaper_history_make_fuzzy_key(const char *value, char *out,
                                   size_t out_cap);
bool cmaper_history_fuzzy_equal(const char *left, const char *right);
bool cmaper_history_fuzzy_contains(const char *haystack, const char *needle);
int cmaper_history_compare_ip(const char *left, const char *right);
int cmaper_history_compare_ids(const char *left, const char *right);

#endif
