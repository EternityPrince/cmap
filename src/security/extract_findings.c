#include "cmaper/security/extract.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "cmaper/security/internal/extract_internal.h"

static bool cmaper_security_is_security_signal(const char *script_id,
                                               const char *output) {
  if (cmaper_security_contains_ci(output, "cve-") ||
      cmaper_security_contains_ci(output, "cwe-") ||
      cmaper_security_contains_ci(output, "ghsa-") ||
      cmaper_security_contains_ci(output, "vulnerable") ||
      cmaper_security_contains_ci(output, "exploit") ||
      cmaper_security_contains_ci(output, "exposed") ||
      cmaper_security_contains_ci(output, "security issue") ||
      cmaper_security_contains_ci(output, "risk")) {
    return true;
  }

  return cmaper_security_contains_ci(script_id, "vuln") ||
         cmaper_security_contains_ci(script_id, "vulner") ||
         cmaper_security_contains_ci(script_id, "security") ||
         cmaper_security_contains_ci(script_id, "heartbleed") ||
         cmaper_security_contains_ci(script_id, "auth-bypass");
}

static cmaper_security_severity_t
cmaper_security_infer_severity(const char *script_id, const char *output) {
  if (cmaper_security_contains_ci(output, "critical")) {
    return CMAPER_SECURITY_SEVERITY_CRITICAL;
  }
  if (cmaper_security_contains_ci(output, "high")) {
    return CMAPER_SECURITY_SEVERITY_HIGH;
  }
  if (cmaper_security_contains_ci(output, "medium") ||
      cmaper_security_contains_ci(output, "moderate")) {
    return CMAPER_SECURITY_SEVERITY_MEDIUM;
  }
  if (cmaper_security_contains_ci(output, "low")) {
    return CMAPER_SECURITY_SEVERITY_LOW;
  }
  if (cmaper_security_contains_ci(output, "informational") ||
      cmaper_security_contains_ci(output, "info")) {
    return CMAPER_SECURITY_SEVERITY_INFO;
  }
  if (cmaper_security_contains_ci(output, "cve-") ||
      cmaper_security_contains_ci(script_id, "vuln") ||
      cmaper_security_contains_ci(output, "vulnerable")) {
    return CMAPER_SECURITY_SEVERITY_MEDIUM;
  }

  return CMAPER_SECURITY_SEVERITY_UNKNOWN;
}

static cmaper_security_finding_state_t
cmaper_security_infer_state(const char *output) {
  if (cmaper_security_contains_ci(output, "not vulnerable") ||
      cmaper_security_contains_ci(output, "patched") ||
      cmaper_security_contains_ci(output, "fixed") ||
      cmaper_security_contains_ci(output, "mitigated")) {
    return CMAPER_SECURITY_FINDING_STATE_RESOLVED;
  }

  if (cmaper_security_contains_ci(output, "vulnerable") ||
      cmaper_security_contains_ci(output, "exposed") ||
      cmaper_security_contains_ci(output, "open") ||
      cmaper_security_contains_ci(output, "affected")) {
    return CMAPER_SECURITY_FINDING_STATE_OPEN;
  }

  return CMAPER_SECURITY_FINDING_STATE_UNKNOWN;
}

static bool cmaper_security_identifier_exists(
    const char identifiers[][CMAPER_SECURITY_FINDING_KEY_CAP], size_t count,
    const char *candidate) {
  size_t i;
  for (i = 0; i < count; ++i) {
    if (strcmp(identifiers[i], candidate) == 0) {
      return true;
    }
  }
  return false;
}

static void cmaper_security_collect_identifier(const char *start,
                                               size_t max_len, char *out,
                                               size_t out_cap) {
  size_t i = 0;
  if (out == NULL || out_cap == 0) {
    return;
  }
  out[0] = '\0';
  while (i < max_len && start[i] != '\0' &&
         !cmaper_security_token_is_boundary(start[i])) {
    if (i + 1U >= out_cap) {
      break;
    }
    out[i] = (char)toupper((unsigned char)start[i]);
    i += 1U;
  }
  out[i] = '\0';
}

static size_t cmaper_security_collect_identifiers(
    const char *text, char identifiers[][CMAPER_SECURITY_FINDING_KEY_CAP],
    size_t id_cap) {
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
      cmaper_security_collect_identifier(&text[i], 32U, candidate,
                                         sizeof(candidate));
    } else if (cmaper_security_starts_with_ci(&text[i], "CWE-")) {
      cmaper_security_collect_identifier(&text[i], 24U, candidate,
                                         sizeof(candidate));
    } else if (cmaper_security_starts_with_ci(&text[i], "GHSA-")) {
      cmaper_security_collect_identifier(&text[i], 32U, candidate,
                                         sizeof(candidate));
    } else {
      continue;
    }

    if (candidate[0] == '\0') {
      continue;
    }
    if (cmaper_security_identifier_exists(identifiers, count, candidate)) {
      continue;
    }

    cmaper_security_copy_string(identifiers[count],
                                CMAPER_SECURITY_FINDING_KEY_CAP, candidate);
    count += 1U;
  }

  return count;
}

static void cmaper_security_humanize_script_id(const char *script_id, char *out,
                                               size_t out_cap) {
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
    unsigned char ch = (unsigned char)script_id[in_index++];
    if (ch == '-' || ch == '_' || ch == '/' || ch == '.') {
      if (out_index > 0 && out[out_index - 1U] != ' ' &&
          out_index + 1U < out_cap) {
        out[out_index++] = ' ';
      }
      new_word = true;
      continue;
    }

    if (new_word) {
      out[out_index++] = (char)toupper(ch);
      new_word = false;
    } else {
      out[out_index++] = (char)ch;
    }
  }
  out[out_index] = '\0';
}

static void cmaper_security_make_title(const char *key, const char *script_id,
                                       char *out, size_t out_cap) {
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

  cmaper_security_humanize_script_id(script_id, script_title,
                                     sizeof(script_title));
  snprintf(out, out_cap, "Potential issue from %s", script_title);
}

size_t
cmaper_security_extract_findings(const cmaper_security_script_input_t *input,
                                 cmaper_security_finding_t *out_items,
                                 size_t out_cap) {
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
      input->output, identifiers, sizeof(identifiers) / sizeof(identifiers[0]));

  if (identifier_count == 0 &&
      !cmaper_security_is_security_signal(input->script_id, input->output)) {
    return 0;
  }

  cmaper_security_normalize_spaces(input->output, normalized_detail,
                                   sizeof(normalized_detail), false);

  severity = cmaper_security_infer_severity(input->script_id, input->output);
  state = cmaper_security_infer_state(input->output);

  if (identifier_count == 0) {
    identifier_count = 1;
    snprintf(identifiers[0], sizeof(identifiers[0]), "script:%s",
             input->script_id);
  }

  if (identifier_count > out_cap) {
    identifier_count = out_cap;
  }

  for (i = 0; i < identifier_count; ++i) {
    cmaper_security_finding_init(&out_items[i]);
    cmaper_security_copy_string(out_items[i].key, sizeof(out_items[i].key),
                                identifiers[i]);
    out_items[i].severity = severity;
    out_items[i].state = state;
    cmaper_security_make_title(out_items[i].key, input->script_id,
                               out_items[i].title, sizeof(out_items[i].title));
    cmaper_security_copy_string(
        out_items[i].detail, sizeof(out_items[i].detail),
        normalized_detail[0] != '\0' ? normalized_detail : input->output);
    cmaper_security_set_script_source(input, out_items[i].source_script,
                                      sizeof(out_items[i].source_script));
  }

  return identifier_count;
}
