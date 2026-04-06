#include "cmaper/scan/script_pipeline.h"

static const cmaper_scan_script_set_info_t CMAPER_SCAN_SCRIPT_SET_ITEMS[] = {
    {
        CMAPER_SCAN_SCRIPT_SET_NMAP_DEFAULT,
        "nmap-default",
        "Run Nmap default scripts with extra LAN hostname probes.",
        "default,ssl-cert,smb-os-discovery,nbstat"
    },
    {
        CMAPER_SCAN_SCRIPT_SET_WEB_BASELINE,
        "web-baseline",
        "Run baseline HTTP scripts for basic web surface checks.",
        "http-title,http-headers,http-server-header"
    },
    {
        CMAPER_SCAN_SCRIPT_SET_TLS_BASELINE,
        "tls-baseline",
        "Run baseline TLS scripts for certificate and cipher details.",
        "ssl-cert,ssl-enum-ciphers"
    },
    {
        CMAPER_SCAN_SCRIPT_SET_DNS_BASELINE,
        "dns-baseline",
        "Run baseline DNS scripts for version and recursion hints.",
        "dns-nsid,dns-recursion"
    },
    {
        CMAPER_SCAN_SCRIPT_SET_SMB_BASELINE,
        "smb-baseline",
        "Run baseline SMB scripts for dialect and security mode checks.",
        "smb-os-discovery,smb-security-mode,smb2-security-mode"
    }
};

size_t cmaper_scan_script_set_list(const cmaper_scan_script_set_info_t **out_items) {
    if (out_items != NULL) {
        *out_items = CMAPER_SCAN_SCRIPT_SET_ITEMS;
    }
    return sizeof(CMAPER_SCAN_SCRIPT_SET_ITEMS) / sizeof(CMAPER_SCAN_SCRIPT_SET_ITEMS[0]);
}

const cmaper_scan_script_set_info_t *cmaper_scan_script_set_info(cmaper_scan_script_set_t id) {
    size_t i;
    size_t count = 0;
    const cmaper_scan_script_set_info_t *items = NULL;

    count = cmaper_scan_script_set_list(&items);
    if (items == NULL || count == 0) {
        return NULL;
    }

    for (i = 0; i < count; ++i) {
        if (items[i].id == id) {
            return &items[i];
        }
    }

    return NULL;
}
