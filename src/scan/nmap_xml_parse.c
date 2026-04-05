#include "cmaper/scan/nmap_xml_parse.h"

#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

static bool cmaper_nmap_xml_node_is(const xmlNode *node, const char *name) {
    if (node == NULL || name == NULL) {
        return false;
    }

    return node->type == XML_ELEMENT_NODE
        && node->name != NULL
        && strcmp((const char *) node->name, name) == 0;
}

static char *cmaper_nmap_xml_attr_dup(const xmlNode *node, const char *name) {
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

static int cmaper_nmap_xml_attr_int(const xmlNode *node, const char *name, int default_value) {
    xmlChar *value;
    char *end = NULL;
    long parsed;

    if (node == NULL || name == NULL) {
        return default_value;
    }

    value = xmlGetProp((xmlNode *) node, (const xmlChar *) name);
    if (value == NULL) {
        return default_value;
    }

    parsed = strtol((const char *) value, &end, 10);
    xmlFree(value);

    if (end == NULL || *end != '\0' || parsed < INT_MIN || parsed > INT_MAX) {
        return default_value;
    }

    return (int) parsed;
}

static void cmaper_nmap_xml_script_dispose(cmaper_nmap_xml_script_t *script) {
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

static void cmaper_nmap_xml_address_dispose(cmaper_nmap_xml_address_t *address) {
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

static void cmaper_nmap_xml_hostname_dispose(cmaper_nmap_xml_hostname_t *hostname) {
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

static void cmaper_nmap_xml_port_dispose(cmaper_nmap_xml_port_t *port) {
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

static void cmaper_nmap_xml_osmatch_dispose(cmaper_nmap_xml_osmatch_t *osmatch) {
    if (osmatch == NULL) {
        return;
    }

    if (osmatch->name != NULL) {
        free(osmatch->name);
        osmatch->name = NULL;
    }
}

static void cmaper_nmap_xml_trace_hop_dispose(cmaper_nmap_xml_trace_hop_t *hop) {
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

static void cmaper_nmap_xml_host_dispose(cmaper_nmap_xml_host_t *host) {
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

static cmaper_err_t cmaper_nmap_xml_append_script(
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

static cmaper_err_t cmaper_nmap_xml_append_address(
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

static cmaper_err_t cmaper_nmap_xml_append_hostname(
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

static cmaper_err_t cmaper_nmap_xml_append_port(
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

static cmaper_err_t cmaper_nmap_xml_append_osmatch(
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

static cmaper_err_t cmaper_nmap_xml_append_trace_hop(
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

static cmaper_err_t cmaper_nmap_xml_append_host(
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

static cmaper_err_t cmaper_nmap_xml_parse_script_node(
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

static cmaper_err_t cmaper_nmap_xml_parse_script_list(
    const xmlNode *container_node,
    cmaper_nmap_xml_script_t **items,
    size_t *count
) {
    const xmlNode *child;

    for (child = container_node->children; child != NULL; child = child->next) {
        cmaper_nmap_xml_script_t script;
        cmaper_err_t rc;

        if (!cmaper_nmap_xml_node_is(child, "script")) {
            continue;
        }

        script.id = NULL;
        script.output = NULL;

        rc = cmaper_nmap_xml_parse_script_node(child, &script);
        if (rc != CMAPER_OK) {
            return rc;
        }

        rc = cmaper_nmap_xml_append_script(items, count, script);
        if (rc != CMAPER_OK) {
            if (script.id != NULL) {
                free(script.id);
            }
            if (script.output != NULL) {
                free(script.output);
            }
            return rc;
        }
    }

    return CMAPER_OK;
}

static cmaper_err_t cmaper_nmap_xml_parse_ports(
    const xmlNode *ports_node,
    cmaper_nmap_xml_host_t *host
) {
    const xmlNode *port_node;

    for (port_node = ports_node->children; port_node != NULL; port_node = port_node->next) {
        const xmlNode *child;
        cmaper_nmap_xml_port_t port;
        cmaper_err_t rc;

        if (!cmaper_nmap_xml_node_is(port_node, "port")) {
            continue;
        }

        memset(&port, 0, sizeof(port));
        port.portid = -1;

        port.protocol = cmaper_nmap_xml_attr_dup(port_node, "protocol");
        port.portid = cmaper_nmap_xml_attr_int(port_node, "portid", -1);

        for (child = port_node->children; child != NULL; child = child->next) {
            if (cmaper_nmap_xml_node_is(child, "state")) {
                port.state = cmaper_nmap_xml_attr_dup(child, "state");
                port.reason = cmaper_nmap_xml_attr_dup(child, "reason");
            } else if (cmaper_nmap_xml_node_is(child, "service")) {
                port.service_name = cmaper_nmap_xml_attr_dup(child, "name");
                port.service_product = cmaper_nmap_xml_attr_dup(child, "product");
                port.service_version = cmaper_nmap_xml_attr_dup(child, "version");
            } else if (cmaper_nmap_xml_node_is(child, "script")) {
                cmaper_nmap_xml_script_t script;

                script.id = NULL;
                script.output = NULL;
                rc = cmaper_nmap_xml_parse_script_node(child, &script);
                if (rc != CMAPER_OK) {
                    cmaper_nmap_xml_port_dispose(&port);
                    return rc;
                }
                rc = cmaper_nmap_xml_append_script(&port.scripts, &port.script_count, script);
                if (rc != CMAPER_OK) {
                    if (script.id != NULL) {
                        free(script.id);
                    }
                    if (script.output != NULL) {
                        free(script.output);
                    }
                    cmaper_nmap_xml_port_dispose(&port);
                    return rc;
                }
            }
        }

        rc = cmaper_nmap_xml_append_port(&host->ports, &host->port_count, port);
        if (rc != CMAPER_OK) {
            cmaper_nmap_xml_port_dispose(&port);
            return rc;
        }
    }

    return CMAPER_OK;
}

static cmaper_err_t cmaper_nmap_xml_parse_host(
    const xmlNode *host_node,
    cmaper_nmap_xml_host_t *host
) {
    const xmlNode *child;

    memset(host, 0, sizeof(*host));

    for (child = host_node->children; child != NULL; child = child->next) {
        if (cmaper_nmap_xml_node_is(child, "status")) {
            host->status.state = cmaper_nmap_xml_attr_dup(child, "state");
            host->status.reason = cmaper_nmap_xml_attr_dup(child, "reason");
        } else if (cmaper_nmap_xml_node_is(child, "address")) {
            cmaper_nmap_xml_address_t address;
            cmaper_err_t rc;

            address.addr = cmaper_nmap_xml_attr_dup(child, "addr");
            address.addrtype = cmaper_nmap_xml_attr_dup(child, "addrtype");
            address.vendor = cmaper_nmap_xml_attr_dup(child, "vendor");
            rc = cmaper_nmap_xml_append_address(&host->addresses, &host->address_count, address);
            if (rc != CMAPER_OK) {
                if (address.addr != NULL) {
                    free(address.addr);
                }
                if (address.addrtype != NULL) {
                    free(address.addrtype);
                }
                if (address.vendor != NULL) {
                    free(address.vendor);
                }
                cmaper_nmap_xml_host_dispose(host);
                return rc;
            }
        } else if (cmaper_nmap_xml_node_is(child, "hostnames")) {
            const xmlNode *hostname_node;

            for (hostname_node = child->children;
                hostname_node != NULL;
                hostname_node = hostname_node->next) {
                cmaper_nmap_xml_hostname_t hostname;
                cmaper_err_t rc;

                if (!cmaper_nmap_xml_node_is(hostname_node, "hostname")) {
                    continue;
                }

                hostname.name = cmaper_nmap_xml_attr_dup(hostname_node, "name");
                hostname.type = cmaper_nmap_xml_attr_dup(hostname_node, "type");
                rc = cmaper_nmap_xml_append_hostname(
                    &host->hostnames,
                    &host->hostname_count,
                    hostname
                );
                if (rc != CMAPER_OK) {
                    if (hostname.name != NULL) {
                        free(hostname.name);
                    }
                    if (hostname.type != NULL) {
                        free(hostname.type);
                    }
                    cmaper_nmap_xml_host_dispose(host);
                    return rc;
                }
            }
        } else if (cmaper_nmap_xml_node_is(child, "ports")) {
            cmaper_err_t rc = cmaper_nmap_xml_parse_ports(child, host);
            if (rc != CMAPER_OK) {
                cmaper_nmap_xml_host_dispose(host);
                return rc;
            }
        } else if (cmaper_nmap_xml_node_is(child, "hostscript")) {
            cmaper_err_t rc = cmaper_nmap_xml_parse_script_list(
                child,
                &host->host_scripts,
                &host->host_script_count
            );
            if (rc != CMAPER_OK) {
                cmaper_nmap_xml_host_dispose(host);
                return rc;
            }
        } else if (cmaper_nmap_xml_node_is(child, "os")) {
            const xmlNode *os_node;

            for (os_node = child->children; os_node != NULL; os_node = os_node->next) {
                cmaper_nmap_xml_osmatch_t osmatch;
                cmaper_err_t rc;

                if (!cmaper_nmap_xml_node_is(os_node, "osmatch")) {
                    continue;
                }

                osmatch.name = cmaper_nmap_xml_attr_dup(os_node, "name");
                osmatch.accuracy = cmaper_nmap_xml_attr_int(os_node, "accuracy", -1);
                osmatch.line = cmaper_nmap_xml_attr_int(os_node, "line", -1);
                rc = cmaper_nmap_xml_append_osmatch(&host->os_matches, &host->os_match_count, osmatch);
                if (rc != CMAPER_OK) {
                    if (osmatch.name != NULL) {
                        free(osmatch.name);
                    }
                    cmaper_nmap_xml_host_dispose(host);
                    return rc;
                }
            }
        } else if (cmaper_nmap_xml_node_is(child, "trace")) {
            const xmlNode *hop_node;

            for (hop_node = child->children; hop_node != NULL; hop_node = hop_node->next) {
                cmaper_nmap_xml_trace_hop_t hop;
                cmaper_err_t rc;

                if (!cmaper_nmap_xml_node_is(hop_node, "hop")) {
                    continue;
                }

                hop.ttl = cmaper_nmap_xml_attr_int(hop_node, "ttl", -1);
                hop.ipaddr = cmaper_nmap_xml_attr_dup(hop_node, "ipaddr");
                hop.rtt = cmaper_nmap_xml_attr_dup(hop_node, "rtt");
                hop.host = cmaper_nmap_xml_attr_dup(hop_node, "host");
                rc = cmaper_nmap_xml_append_trace_hop(&host->trace_hops, &host->trace_hop_count, hop);
                if (rc != CMAPER_OK) {
                    if (hop.ipaddr != NULL) {
                        free(hop.ipaddr);
                    }
                    if (hop.rtt != NULL) {
                        free(hop.rtt);
                    }
                    if (hop.host != NULL) {
                        free(hop.host);
                    }
                    cmaper_nmap_xml_host_dispose(host);
                    return rc;
                }
            }
        }
    }

    return CMAPER_OK;
}

static void cmaper_nmap_xml_parse_runstats(
    const xmlNode *runstats_node,
    cmaper_nmap_xml_document_t *document
) {
    const xmlNode *child;

    for (child = runstats_node->children; child != NULL; child = child->next) {
        if (cmaper_nmap_xml_node_is(child, "finished")) {
            document->runstats.time = cmaper_nmap_xml_attr_dup(child, "time");
            document->runstats.timestr = cmaper_nmap_xml_attr_dup(child, "timestr");
            document->runstats.elapsed = cmaper_nmap_xml_attr_dup(child, "elapsed");
            document->runstats.summary = cmaper_nmap_xml_attr_dup(child, "summary");
            document->runstats.exit_status = cmaper_nmap_xml_attr_dup(child, "exit");
        } else if (cmaper_nmap_xml_node_is(child, "hosts")) {
            document->runstats.hosts_up = cmaper_nmap_xml_attr_int(child, "up", -1);
            document->runstats.hosts_down = cmaper_nmap_xml_attr_int(child, "down", -1);
            document->runstats.hosts_total = cmaper_nmap_xml_attr_int(child, "total", -1);
        }
    }
}

cmaper_err_t cmaper_nmap_xml_parse_memory(
    const char *xml_data,
    size_t xml_size,
    cmaper_nmap_xml_document_t *document,
    cmaper_nmap_xml_diag_t *diag
) {
    xmlDocPtr xml_doc = NULL;
    xmlNode *root;
    xmlNode *child;
    cmaper_err_t rc = CMAPER_OK;

    if (xml_data == NULL || document == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    if (xml_size > (size_t) INT_MAX) {
        cmaper_nmap_xml_diag_setf(diag, "xml", "xml input is too large for parser");
        return CMAPER_ERR_PARSE;
    }

    cmaper_nmap_xml_diag_clear(diag);
    cmaper_nmap_xml_document_dispose(document);
    cmaper_nmap_xml_document_init(document);

    xml_doc = xmlReadMemory(
        xml_data,
        (int) xml_size,
        "nmap.xml",
        NULL,
        XML_PARSE_NONET | XML_PARSE_NOBLANKS
    );
    if (xml_doc == NULL) {
        cmaper_nmap_xml_diag_setf(diag, "xml", "failed to parse nmap xml document");
        return CMAPER_ERR_PARSE;
    }

    root = xmlDocGetRootElement(xml_doc);
    if (root == NULL || !cmaper_nmap_xml_node_is(root, "nmaprun")) {
        cmaper_nmap_xml_diag_setf(diag, "xml", "nmap xml root element 'nmaprun' is missing");
        rc = CMAPER_ERR_PARSE;
        goto cleanup;
    }

    document->run.scanner = cmaper_nmap_xml_attr_dup(root, "scanner");
    document->run.args = cmaper_nmap_xml_attr_dup(root, "args");
    document->run.start = cmaper_nmap_xml_attr_dup(root, "start");
    document->run.startstr = cmaper_nmap_xml_attr_dup(root, "startstr");
    document->run.version = cmaper_nmap_xml_attr_dup(root, "version");
    document->run.xmloutputversion = cmaper_nmap_xml_attr_dup(root, "xmloutputversion");

    for (child = root->children; child != NULL; child = child->next) {
        if (cmaper_nmap_xml_node_is(child, "host")) {
            cmaper_nmap_xml_host_t host;

            rc = cmaper_nmap_xml_parse_host(child, &host);
            if (rc != CMAPER_OK) {
                cmaper_nmap_xml_diag_setf(diag, "host", "failed to parse host block");
                rc = CMAPER_ERR_PARSE;
                goto cleanup;
            }

            rc = cmaper_nmap_xml_append_host(document, host);
            if (rc != CMAPER_OK) {
                cmaper_nmap_xml_host_dispose(&host);
                cmaper_nmap_xml_diag_setf(diag, "host", "failed to append parsed host");
                goto cleanup;
            }
        } else if (cmaper_nmap_xml_node_is(child, "runstats")) {
            cmaper_nmap_xml_parse_runstats(child, document);
        }
    }

cleanup:
    if (xml_doc != NULL) {
        xmlFreeDoc(xml_doc);
    }

    if (rc != CMAPER_OK) {
        cmaper_nmap_xml_document_dispose(document);
        cmaper_nmap_xml_document_init(document);
    }

    return rc;
}
