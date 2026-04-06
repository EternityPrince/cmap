#ifndef CMAPER_SCAN_NMAP_XML_PARSE_H
#define CMAPER_SCAN_NMAP_XML_PARSE_H

#include <stddef.h>

#include "cmaper/core/error.h"
#include "cmaper/scan/nmap_xml_model.h"

#define CMAPER_NMAP_XML_DIAG_CAP 256

typedef struct {
    const char *field;
    char message[CMAPER_NMAP_XML_DIAG_CAP];
} cmaper_nmap_xml_diag_t;

void cmaper_nmap_xml_diag_clear(cmaper_nmap_xml_diag_t *diag);
void cmaper_nmap_xml_diag_setf(
    cmaper_nmap_xml_diag_t *diag,
    const char *field,
    const char *fmt,
    ...
);

cmaper_err_t cmaper_nmap_xml_parse_memory(
    const char *xml_data,
    size_t xml_size,
    cmaper_nmap_xml_document_t *document,
    cmaper_nmap_xml_diag_t *diag
);

#endif
