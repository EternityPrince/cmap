#include "cmaper/scan/source_identity.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

static size_t cmaper_scan_copy_token(
    char *out,
    size_t out_cap,
    const char *value
) {
    size_t i = 0;

    if (out == NULL || out_cap == 0) {
        return 0;
    }

    out[0] = '\0';
    if (value == NULL) {
        return 0;
    }

    while (value[i] != '\0'
        && value[i] != ','
        && value[i] != ' '
        && value[i] != '\t'
        && value[i] != '\n'
        && value[i] != '\r') {
        if (i + 1 >= out_cap) {
            out[i] = '\0';
            return i;
        }
        out[i] = value[i];
        ++i;
    }

    out[i] = '\0';
    return i;
}

static bool cmaper_scan_is_loopback_target(const char *target) {
    if (target == NULL || target[0] == '\0') {
        return false;
    }

    if (strcmp(target, "localhost") == 0
        || strcmp(target, "::1") == 0
        || strcmp(target, "127.0.0.1") == 0) {
        return true;
    }

    if (strncmp(target, "127.", 4) == 0) {
        return true;
    }

    return false;
}

static bool cmaper_scan_random_fill(unsigned char *bytes, size_t count) {
    FILE *stream;
    size_t read_count;

    if (bytes == NULL || count == 0) {
        return false;
    }

    stream = fopen("/dev/urandom", "rb");
    if (stream == NULL) {
        return false;
    }

    read_count = fread(bytes, 1, count, stream);
    fclose(stream);

    return read_count == count;
}

static cmaper_err_t cmaper_scan_random_mac_generate(char *out, size_t out_cap) {
    unsigned char bytes[6];

    if (out == NULL || out_cap == 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    out[0] = '\0';
    if (out_cap < 18) {
        return CMAPER_ERR_IO;
    }

    if (!cmaper_scan_random_fill(bytes, sizeof(bytes))) {
        return CMAPER_ERR_IO;
    }

    /* Force locally administered unicast MAC address. */
    bytes[0] = (unsigned char) ((bytes[0] | 0x02u) & 0xFEu);

    if (snprintf(
            out,
            out_cap,
            "%02X:%02X:%02X:%02X:%02X:%02X",
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5]) >= (int) out_cap) {
        return CMAPER_ERR_IO;
    }

    return CMAPER_OK;
}

void cmaper_scan_source_identity_init(cmaper_scan_source_identity_t *identity) {
    if (identity == NULL) {
        return;
    }

    identity->mode = CMAPER_SCAN_SOURCE_IDENTITY_UNSET;
    identity->representative_target[0] = '\0';
    identity->representative_is_cidr = false;
    identity->representative_is_loopback = false;
    identity->has_interface = false;
    identity->interface_name[0] = '\0';
    identity->has_real_mac = false;
    identity->real_mac[0] = '\0';
    identity->spoof_requested = false;
    identity->spoof_is_random = false;
    identity->has_spoofed_mac = false;
    identity->spoofed_mac[0] = '\0';
}

cmaper_err_t cmaper_scan_source_identity_resolve(
    const cmaper_scan_plan_t *plan,
    cmaper_scan_source_identity_t *identity
) {
    if (plan == NULL || identity == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_scan_source_identity_init(identity);

    cmaper_scan_copy_token(
        identity->representative_target,
        sizeof(identity->representative_target),
        plan->target
    );

    identity->representative_is_cidr = strchr(identity->representative_target, '/') != NULL;
    identity->representative_is_loopback =
        cmaper_scan_is_loopback_target(identity->representative_target);

    identity->spoof_requested = plan->spoof_mac_mode != CMAPER_SCAN_SPOOF_MAC_OFF;
    if (plan->spoof_mac_mode == CMAPER_SCAN_SPOOF_MAC_RANDOM) {
        cmaper_err_t rc = cmaper_scan_random_mac_generate(
            identity->spoofed_mac,
            sizeof(identity->spoofed_mac)
        );
        if (rc != CMAPER_OK) {
            return rc;
        }

        identity->spoof_is_random = true;
        identity->has_spoofed_mac = true;
    } else if (plan->spoof_mac_mode == CMAPER_SCAN_SPOOF_MAC_CUSTOM
        && plan->spoof_mac_value != NULL
        && plan->spoof_mac_value[0] != '\0') {
        identity->spoof_is_random = false;
        identity->has_spoofed_mac = true;
        snprintf(identity->spoofed_mac, sizeof(identity->spoofed_mac), "%s", plan->spoof_mac_value);
    }

    identity->mode = CMAPER_SCAN_SOURCE_IDENTITY_FALLBACK;

    return CMAPER_OK;
}

const char *cmaper_scan_source_identity_mode_name(cmaper_scan_source_identity_mode_t mode) {
    switch (mode) {
    case CMAPER_SCAN_SOURCE_IDENTITY_FALLBACK:
        return "fallback";
    case CMAPER_SCAN_SOURCE_IDENTITY_UNSET:
        break;
    }

    return "unset";
}
