#include "cmaper/history/internal/query_internal.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static void cmaper_history_detail_text_mark_truncated(char *out, size_t out_cap) {
    if (out == NULL || out_cap < 4U) {
        return;
    }
    out[out_cap - 4U] = '.';
    out[out_cap - 3U] = '.';
    out[out_cap - 2U] = '.';
    out[out_cap - 1U] = '\0';
}

void cmaper_history_detail_text_clear(char *out, size_t out_cap) {
    if (out == NULL || out_cap == 0U) {
        return;
    }
    out[0] = '\0';
}

void cmaper_history_detail_text_append(char *out, size_t out_cap, const char *token) {
    size_t len;
    int written;

    if (out == NULL || out_cap == 0U || token == NULL || token[0] == '\0') {
        return;
    }

    len = strlen(out);
    if (len >= out_cap - 1U) {
        return;
    }

    written = snprintf(
        out + len,
        out_cap - len,
        "%s%s",
        len == 0U ? "" : ", ",
        token
    );
    if (written < 0 || (size_t) written >= (out_cap - len)) {
        cmaper_history_detail_text_mark_truncated(out, out_cap);
    }
}

void cmaper_history_detail_text_append_line(char *out, size_t out_cap, const char *line) {
    size_t len;
    int written;

    if (out == NULL || out_cap == 0U || line == NULL || line[0] == '\0') {
        return;
    }

    len = strlen(out);
    if (len >= out_cap - 1U) {
        return;
    }

    written = snprintf(
        out + len,
        out_cap - len,
        "%s%s",
        len == 0U ? "" : "\n",
        line
    );
    if (written < 0 || (size_t) written >= (out_cap - len)) {
        cmaper_history_detail_text_mark_truncated(out, out_cap);
    }
}

void cmaper_history_detail_text_compact_copy(
    char *out,
    size_t out_cap,
    const char *value,
    size_t max_chars
) {
    size_t src = 0U;
    size_t dst = 0U;
    bool last_space = false;
    bool truncated = false;

    if (out == NULL || out_cap == 0U) {
        return;
    }
    out[0] = '\0';
    if (value == NULL || value[0] == '\0') {
        return;
    }

    while (value[src] != '\0') {
        char ch = value[src];
        if (ch == '\n' || ch == '\r' || ch == '\t') {
            ch = ' ';
        }

        if (ch == ' ') {
            if (last_space) {
                src += 1U;
                continue;
            }
            last_space = true;
        } else {
            last_space = false;
        }

        if (dst + 1U >= out_cap || dst >= max_chars) {
            truncated = true;
            break;
        }
        out[dst++] = ch;
        src += 1U;
    }

    while (dst > 0U && out[dst - 1U] == ' ') {
        dst -= 1U;
    }
    out[dst] = '\0';

    if (truncated && dst + 4U < out_cap) {
        out[dst++] = '.';
        out[dst++] = '.';
        out[dst++] = '.';
        out[dst] = '\0';
    }
}
