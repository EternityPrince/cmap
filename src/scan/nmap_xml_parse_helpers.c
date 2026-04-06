#include "cmaper/scan/internal/nmap_xml_parse_internal.h"

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool cmaper_nmap_xml_node_is(const xmlNode *node, const char *name) {
    if (node == NULL || name == NULL) {
        return false;
    }

    return node->type == XML_ELEMENT_NODE
        && node->name != NULL
        && strcmp((const char *) node->name, name) == 0;
}

char *cmaper_nmap_xml_attr_dup(const xmlNode *node, const char *name) {
    xmlChar *value;
    char *copy;
    size_t length;

    if (node == NULL || name == NULL) {
        return NULL;
    }

    value = xmlGetProp((xmlNode *) node, (const xmlChar *) name);
    if (value == NULL) {
        return NULL;
    }

    length = strlen((const char *) value);
    copy = (char *) malloc(length + 1U);
    if (copy != NULL) {
        memcpy(copy, (const char *) value, length + 1U);
    }
    xmlFree(value);
    return copy;
}

int cmaper_nmap_xml_attr_int(const xmlNode *node, const char *name, int default_value) {
    xmlChar *value;
    char *end = NULL;
    long parsed;
    bool valid = false;

    if (node == NULL || name == NULL) {
        return default_value;
    }

    value = xmlGetProp((xmlNode *) node, (const xmlChar *) name);
    if (value == NULL) {
        return default_value;
    }

    parsed = strtol((const char *) value, &end, 10);
    if (end != NULL && *end == '\0' && parsed >= INT_MIN && parsed <= INT_MAX) {
        valid = true;
    }

    xmlFree(value);

    if (!valid) {
        return default_value;
    }

    return (int) parsed;
}

void cmaper_nmap_xml_script_dispose(cmaper_nmap_xml_script_t *script) {
    if (script == NULL) {
        return;
    }

    if (script->id != NULL) {
        free(script->id);
        script->id = NULL;
    }
    if (script->output != NULL) {
        free(script->output);
        script->output = NULL;
    }
}

void cmaper_nmap_xml_address_dispose(cmaper_nmap_xml_address_t *address) {
    if (address == NULL) {
        return;
    }

    if (address->addr != NULL) {
        free(address->addr);
        address->addr = NULL;
    }
    if (address->addrtype != NULL) {
        free(address->addrtype);
        address->addrtype = NULL;
    }
    if (address->vendor != NULL) {
        free(address->vendor);
        address->vendor = NULL;
    }
}

void cmaper_nmap_xml_hostname_dispose(cmaper_nmap_xml_hostname_t *hostname) {
    if (hostname == NULL) {
        return;
    }

    if (hostname->name != NULL) {
        free(hostname->name);
        hostname->name = NULL;
    }
    if (hostname->type != NULL) {
        free(hostname->type);
        hostname->type = NULL;
    }
}

void cmaper_nmap_xml_port_dispose(cmaper_nmap_xml_port_t *port) {
    size_t i;

    if (port == NULL) {
        return;
    }

    if (port->protocol != NULL) {
        free(port->protocol);
        port->protocol = NULL;
    }
    if (port->state != NULL) {
        free(port->state);
        port->state = NULL;
    }
    if (port->reason != NULL) {
        free(port->reason);
        port->reason = NULL;
    }
    if (port->service_name != NULL) {
        free(port->service_name);
        port->service_name = NULL;
    }
    if (port->service_product != NULL) {
        free(port->service_product);
        port->service_product = NULL;
    }
    if (port->service_version != NULL) {
        free(port->service_version);
        port->service_version = NULL;
    }

    if (port->scripts != NULL) {
        for (i = 0; i < port->script_count; ++i) {
            cmaper_nmap_xml_script_dispose(&port->scripts[i]);
        }
        free(port->scripts);
        port->scripts = NULL;
    }
    port->script_count = 0;
}

void cmaper_nmap_xml_osmatch_dispose(cmaper_nmap_xml_osmatch_t *osmatch) {
    if (osmatch == NULL) {
        return;
    }

    if (osmatch->name != NULL) {
        free(osmatch->name);
        osmatch->name = NULL;
    }
}

void cmaper_nmap_xml_trace_hop_dispose(cmaper_nmap_xml_trace_hop_t *hop) {
    if (hop == NULL) {
        return;
    }

    if (hop->ipaddr != NULL) {
        free(hop->ipaddr);
        hop->ipaddr = NULL;
    }
    if (hop->rtt != NULL) {
        free(hop->rtt);
        hop->rtt = NULL;
    }
    if (hop->host != NULL) {
        free(hop->host);
        hop->host = NULL;
    }
}

void cmaper_nmap_xml_host_dispose(cmaper_nmap_xml_host_t *host) {
    size_t i;

    if (host == NULL) {
        return;
    }

    if (host->status.state != NULL) {
        free(host->status.state);
        host->status.state = NULL;
    }
    if (host->status.reason != NULL) {
        free(host->status.reason);
        host->status.reason = NULL;
    }

    if (host->addresses != NULL) {
        for (i = 0; i < host->address_count; ++i) {
            cmaper_nmap_xml_address_dispose(&host->addresses[i]);
        }
        free(host->addresses);
        host->addresses = NULL;
    }
    host->address_count = 0;

    if (host->hostnames != NULL) {
        for (i = 0; i < host->hostname_count; ++i) {
            cmaper_nmap_xml_hostname_dispose(&host->hostnames[i]);
        }
        free(host->hostnames);
        host->hostnames = NULL;
    }
    host->hostname_count = 0;

    if (host->ports != NULL) {
        for (i = 0; i < host->port_count; ++i) {
            cmaper_nmap_xml_port_dispose(&host->ports[i]);
        }
        free(host->ports);
        host->ports = NULL;
    }
    host->port_count = 0;

    if (host->host_scripts != NULL) {
        for (i = 0; i < host->host_script_count; ++i) {
            cmaper_nmap_xml_script_dispose(&host->host_scripts[i]);
        }
        free(host->host_scripts);
        host->host_scripts = NULL;
    }
    host->host_script_count = 0;

    if (host->os_matches != NULL) {
        for (i = 0; i < host->os_match_count; ++i) {
            cmaper_nmap_xml_osmatch_dispose(&host->os_matches[i]);
        }
        free(host->os_matches);
        host->os_matches = NULL;
    }
    host->os_match_count = 0;

    if (host->trace_hops != NULL) {
        for (i = 0; i < host->trace_hop_count; ++i) {
            cmaper_nmap_xml_trace_hop_dispose(&host->trace_hops[i]);
        }
        free(host->trace_hops);
        host->trace_hops = NULL;
    }
    host->trace_hop_count = 0;
}

void cmaper_nmap_xml_diag_clear(cmaper_nmap_xml_diag_t *diag) {
    if (diag == NULL) {
        return;
    }

    diag->field = NULL;
    diag->message[0] = '\0';
}

void cmaper_nmap_xml_diag_setf(
    cmaper_nmap_xml_diag_t *diag,
    const char *field,
    const char *fmt,
    ...
) {
    va_list args;

    cmaper_nmap_xml_diag_clear(diag);
    if (diag == NULL) {
        return;
    }

    diag->field = field;
    if (fmt == NULL) {
        return;
    }

    va_start(args, fmt);
    vsnprintf(diag->message, sizeof(diag->message), fmt, args);
    va_end(args);
}

cmaper_err_t cmaper_nmap_xml_append_script(
    cmaper_nmap_xml_script_t **items,
    size_t *count,
    cmaper_nmap_xml_script_t script
) {
    cmaper_nmap_xml_script_t *next;

    next = (cmaper_nmap_xml_script_t *) realloc(
        *items,
        (*count + 1U) * sizeof(cmaper_nmap_xml_script_t)
    );
    if (next == NULL) {
        return CMAPER_ERR_OOM;
    }

    *items = next;
    (*items)[*count] = script;
    *count += 1U;
    return CMAPER_OK;
}

cmaper_err_t cmaper_nmap_xml_append_address(
    cmaper_nmap_xml_address_t **items,
    size_t *count,
    cmaper_nmap_xml_address_t address
) {
    cmaper_nmap_xml_address_t *next;

    next = (cmaper_nmap_xml_address_t *) realloc(
        *items,
        (*count + 1U) * sizeof(cmaper_nmap_xml_address_t)
    );
    if (next == NULL) {
        return CMAPER_ERR_OOM;
    }

    *items = next;
    (*items)[*count] = address;
    *count += 1U;
    return CMAPER_OK;
}

cmaper_err_t cmaper_nmap_xml_append_hostname(
    cmaper_nmap_xml_hostname_t **items,
    size_t *count,
    cmaper_nmap_xml_hostname_t hostname
) {
    cmaper_nmap_xml_hostname_t *next;

    next = (cmaper_nmap_xml_hostname_t *) realloc(
        *items,
        (*count + 1U) * sizeof(cmaper_nmap_xml_hostname_t)
    );
    if (next == NULL) {
        return CMAPER_ERR_OOM;
    }

    *items = next;
    (*items)[*count] = hostname;
    *count += 1U;
    return CMAPER_OK;
}

cmaper_err_t cmaper_nmap_xml_append_port(
    cmaper_nmap_xml_port_t **items,
    size_t *count,
    cmaper_nmap_xml_port_t port
) {
    cmaper_nmap_xml_port_t *next;

    next = (cmaper_nmap_xml_port_t *) realloc(
        *items,
        (*count + 1U) * sizeof(cmaper_nmap_xml_port_t)
    );
    if (next == NULL) {
        return CMAPER_ERR_OOM;
    }

    *items = next;
    (*items)[*count] = port;
    *count += 1U;
    return CMAPER_OK;
}

cmaper_err_t cmaper_nmap_xml_append_osmatch(
    cmaper_nmap_xml_osmatch_t **items,
    size_t *count,
    cmaper_nmap_xml_osmatch_t osmatch
) {
    cmaper_nmap_xml_osmatch_t *next;

    next = (cmaper_nmap_xml_osmatch_t *) realloc(
        *items,
        (*count + 1U) * sizeof(cmaper_nmap_xml_osmatch_t)
    );
    if (next == NULL) {
        return CMAPER_ERR_OOM;
    }

    *items = next;
    (*items)[*count] = osmatch;
    *count += 1U;
    return CMAPER_OK;
}

cmaper_err_t cmaper_nmap_xml_append_trace_hop(
    cmaper_nmap_xml_trace_hop_t **items,
    size_t *count,
    cmaper_nmap_xml_trace_hop_t hop
) {
    cmaper_nmap_xml_trace_hop_t *next;

    next = (cmaper_nmap_xml_trace_hop_t *) realloc(
        *items,
        (*count + 1U) * sizeof(cmaper_nmap_xml_trace_hop_t)
    );
    if (next == NULL) {
        return CMAPER_ERR_OOM;
    }

    *items = next;
    (*items)[*count] = hop;
    *count += 1U;
    return CMAPER_OK;
}

cmaper_err_t cmaper_nmap_xml_append_host(
    cmaper_nmap_xml_document_t *document,
    cmaper_nmap_xml_host_t host
) {
    cmaper_nmap_xml_host_t *next;

    next = (cmaper_nmap_xml_host_t *) realloc(
        document->hosts,
        (document->host_count + 1U) * sizeof(cmaper_nmap_xml_host_t)
    );
    if (next == NULL) {
        return CMAPER_ERR_OOM;
    }

    document->hosts = next;
    document->hosts[document->host_count] = host;
    document->host_count += 1U;
    return CMAPER_OK;
}

cmaper_err_t cmaper_nmap_xml_parse_script_node(
    const xmlNode *script_node,
    cmaper_nmap_xml_script_t *script
) {
    if (script == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    script->id = cmaper_nmap_xml_attr_dup(script_node, "id");
    script->output = cmaper_nmap_xml_attr_dup(script_node, "output");
    return CMAPER_OK;
}
