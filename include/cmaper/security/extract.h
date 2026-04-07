#ifndef CMAPER_SECURITY_EXTRACT_H
#define CMAPER_SECURITY_EXTRACT_H

#include <stdbool.h>
#include <stddef.h>

#define CMAPER_SECURITY_SCRIPT_ID_CAP 64
#define CMAPER_SECURITY_FINGERPRINT_VALUE_CAP 384
#define CMAPER_SECURITY_FINDING_KEY_CAP 96
#define CMAPER_SECURITY_FINDING_TITLE_CAP 160
#define CMAPER_SECURITY_FINDING_DETAIL_CAP 512
#define CMAPER_SECURITY_SURFACE_TYPE_CAP 64
#define CMAPER_SECURITY_SURFACE_DETAIL_CAP 256

typedef enum {
  CMAPER_SECURITY_FP_TLS = 0,
  CMAPER_SECURITY_FP_SSH,
  CMAPER_SECURITY_FP_HTTP,
  CMAPER_SECURITY_FP_SMB
} cmaper_security_fingerprint_kind_t;

typedef enum {
  CMAPER_SECURITY_SEVERITY_UNKNOWN = 0,
  CMAPER_SECURITY_SEVERITY_INFO,
  CMAPER_SECURITY_SEVERITY_LOW,
  CMAPER_SECURITY_SEVERITY_MEDIUM,
  CMAPER_SECURITY_SEVERITY_HIGH,
  CMAPER_SECURITY_SEVERITY_CRITICAL
} cmaper_security_severity_t;

typedef enum {
  CMAPER_SECURITY_FINDING_STATE_UNKNOWN = 0,
  CMAPER_SECURITY_FINDING_STATE_OPEN,
  CMAPER_SECURITY_FINDING_STATE_RESOLVED
} cmaper_security_finding_state_t;

typedef struct {
  const char *script_id;
  const char *output;
  const char *protocol;
  int port;
  const char *service_name;
} cmaper_security_script_input_t;

typedef struct {
  cmaper_security_fingerprint_kind_t kind;
  char value[CMAPER_SECURITY_FINGERPRINT_VALUE_CAP];
  char source_script[CMAPER_SECURITY_SCRIPT_ID_CAP];
} cmaper_security_fingerprint_t;

typedef struct {
  char key[CMAPER_SECURITY_FINDING_KEY_CAP];
  cmaper_security_severity_t severity;
  cmaper_security_finding_state_t state;
  char title[CMAPER_SECURITY_FINDING_TITLE_CAP];
  char detail[CMAPER_SECURITY_FINDING_DETAIL_CAP];
  char source_script[CMAPER_SECURITY_SCRIPT_ID_CAP];
} cmaper_security_finding_t;

typedef struct {
  char type[CMAPER_SECURITY_SURFACE_TYPE_CAP];
  char detail[CMAPER_SECURITY_SURFACE_DETAIL_CAP];
} cmaper_security_management_surface_t;

typedef struct {
  size_t tls_fingerprints;
  size_t ssh_fingerprints;
  size_t http_fingerprints;
  size_t smb_fingerprints;
  size_t findings_total;
  size_t findings_open;
  size_t findings_high_or_worse;
  size_t management_surfaces;
} cmaper_security_aggregate_t;

void cmaper_security_script_input_init(cmaper_security_script_input_t *input);
void cmaper_security_fingerprint_init(
    cmaper_security_fingerprint_t *fingerprint);
void cmaper_security_finding_init(cmaper_security_finding_t *finding);
void cmaper_security_management_surface_init(
    cmaper_security_management_surface_t *surface);
void cmaper_security_aggregate_init(cmaper_security_aggregate_t *aggregate);

const char *
cmaper_security_fingerprint_kind_name(cmaper_security_fingerprint_kind_t kind);
const char *cmaper_security_severity_name(cmaper_security_severity_t severity);
const char *
cmaper_security_finding_state_name(cmaper_security_finding_state_t state);

bool cmaper_security_normalize_tls_fingerprint(
    const cmaper_security_script_input_t *input,
    cmaper_security_fingerprint_t *out_fingerprint);
bool cmaper_security_normalize_ssh_fingerprint(
    const cmaper_security_script_input_t *input,
    cmaper_security_fingerprint_t *out_fingerprint);
bool cmaper_security_normalize_http_fingerprint(
    const cmaper_security_script_input_t *input,
    cmaper_security_fingerprint_t *out_fingerprint);
bool cmaper_security_normalize_smb_fingerprint(
    const cmaper_security_script_input_t *input,
    cmaper_security_fingerprint_t *out_fingerprint);

size_t
cmaper_security_extract_findings(const cmaper_security_script_input_t *input,
                                 cmaper_security_finding_t *out_items,
                                 size_t out_cap);

size_t cmaper_security_detect_management_surfaces_for_port(
    const char *protocol, int port, const char *service_name,
    cmaper_security_management_surface_t *out_items, size_t out_cap);
size_t cmaper_security_detect_management_surfaces_from_http_title(
    const cmaper_security_script_input_t *input,
    cmaper_security_management_surface_t *out_items, size_t out_cap);

void cmaper_security_aggregate_add_fingerprint(
    cmaper_security_aggregate_t *aggregate,
    const cmaper_security_fingerprint_t *fingerprint);
void cmaper_security_aggregate_add_finding(
    cmaper_security_aggregate_t *aggregate,
    const cmaper_security_finding_t *finding);
void cmaper_security_aggregate_add_surface(
    cmaper_security_aggregate_t *aggregate,
    const cmaper_security_management_surface_t *surface);

#endif
