#include "cmaper/scan/nmap_xml_parse.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "cmaper/scan/internal/nmap_xml_parse_internal.h"

static cmaper_err_t
cmaper_nmap_xml_parse_script_list(const xmlNode *container_node,
                                  cmaper_nmap_xml_script_t **items,
                                  size_t *count) {
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

static cmaper_err_t cmaper_nmap_xml_parse_ports(const xmlNode *ports_node,
                                                cmaper_nmap_xml_host_t *host) {
  const xmlNode *port_node;

  for (port_node = ports_node->children; port_node != NULL;
       port_node = port_node->next) {
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
        rc = cmaper_nmap_xml_append_script(&port.scripts, &port.script_count,
                                           script);
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

static cmaper_err_t cmaper_nmap_xml_parse_host(const xmlNode *host_node,
                                               cmaper_nmap_xml_host_t *host) {
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
      rc = cmaper_nmap_xml_append_address(&host->addresses,
                                          &host->address_count, address);
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

      for (hostname_node = child->children; hostname_node != NULL;
           hostname_node = hostname_node->next) {
        cmaper_nmap_xml_hostname_t hostname;
        cmaper_err_t rc;

        if (!cmaper_nmap_xml_node_is(hostname_node, "hostname")) {
          continue;
        }

        hostname.name = cmaper_nmap_xml_attr_dup(hostname_node, "name");
        hostname.type = cmaper_nmap_xml_attr_dup(hostname_node, "type");
        rc = cmaper_nmap_xml_append_hostname(&host->hostnames,
                                             &host->hostname_count, hostname);
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
          child, &host->host_scripts, &host->host_script_count);
      if (rc != CMAPER_OK) {
        cmaper_nmap_xml_host_dispose(host);
        return rc;
      }
    } else if (cmaper_nmap_xml_node_is(child, "os")) {
      const xmlNode *os_node;

      for (os_node = child->children; os_node != NULL;
           os_node = os_node->next) {
        cmaper_nmap_xml_osmatch_t osmatch;
        cmaper_err_t rc;

        if (!cmaper_nmap_xml_node_is(os_node, "osmatch")) {
          continue;
        }

        osmatch.name = cmaper_nmap_xml_attr_dup(os_node, "name");
        osmatch.accuracy = cmaper_nmap_xml_attr_int(os_node, "accuracy", -1);
        osmatch.line = cmaper_nmap_xml_attr_int(os_node, "line", -1);
        rc = cmaper_nmap_xml_append_osmatch(&host->os_matches,
                                            &host->os_match_count, osmatch);
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

      for (hop_node = child->children; hop_node != NULL;
           hop_node = hop_node->next) {
        cmaper_nmap_xml_trace_hop_t hop;
        cmaper_err_t rc;

        if (!cmaper_nmap_xml_node_is(hop_node, "hop")) {
          continue;
        }

        hop.ttl = cmaper_nmap_xml_attr_int(hop_node, "ttl", -1);
        hop.ipaddr = cmaper_nmap_xml_attr_dup(hop_node, "ipaddr");
        hop.rtt = cmaper_nmap_xml_attr_dup(hop_node, "rtt");
        hop.host = cmaper_nmap_xml_attr_dup(hop_node, "host");
        rc = cmaper_nmap_xml_append_trace_hop(&host->trace_hops,
                                              &host->trace_hop_count, hop);
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

static void
cmaper_nmap_xml_parse_runstats(const xmlNode *runstats_node,
                               cmaper_nmap_xml_document_t *document) {
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
      document->runstats.hosts_down =
          cmaper_nmap_xml_attr_int(child, "down", -1);
      document->runstats.hosts_total =
          cmaper_nmap_xml_attr_int(child, "total", -1);
    }
  }
}

static cmaper_err_t
cmaper_nmap_xml_parse_doc(xmlDocPtr xml_doc,
                          cmaper_nmap_xml_document_t *document,
                          cmaper_nmap_xml_diag_t *diag) {
  xmlNode *root;
  xmlNode *child;
  cmaper_err_t rc = CMAPER_OK;

  if (xml_doc == NULL || document == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  cmaper_nmap_xml_diag_clear(diag);
  cmaper_nmap_xml_document_dispose(document);
  cmaper_nmap_xml_document_init(document);

  root = xmlDocGetRootElement(xml_doc);
  if (root == NULL || !cmaper_nmap_xml_node_is(root, "nmaprun")) {
    cmaper_nmap_xml_diag_setf(diag, "xml",
                              "nmap xml root element 'nmaprun' is missing");
    rc = CMAPER_ERR_PARSE;
    goto cleanup;
  }

  document->run.scanner = cmaper_nmap_xml_attr_dup(root, "scanner");
  document->run.args = cmaper_nmap_xml_attr_dup(root, "args");
  document->run.start = cmaper_nmap_xml_attr_dup(root, "start");
  document->run.startstr = cmaper_nmap_xml_attr_dup(root, "startstr");
  document->run.version = cmaper_nmap_xml_attr_dup(root, "version");
  document->run.xmloutputversion =
      cmaper_nmap_xml_attr_dup(root, "xmloutputversion");

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
  if (rc != CMAPER_OK) {
    cmaper_nmap_xml_document_dispose(document);
    cmaper_nmap_xml_document_init(document);
  }

  return rc;
}

cmaper_err_t cmaper_nmap_xml_parse_memory(const char *xml_data, size_t xml_size,
                                          cmaper_nmap_xml_document_t *document,
                                          cmaper_nmap_xml_diag_t *diag) {
  xmlDocPtr xml_doc = NULL;
  cmaper_err_t rc;

  if (xml_data == NULL || document == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  if (xml_size > (size_t)INT_MAX) {
    cmaper_nmap_xml_diag_setf(diag, "xml", "xml input is too large for parser");
    return CMAPER_ERR_PARSE;
  }

  xml_doc = xmlReadMemory(xml_data, (int)xml_size, "nmap.xml", NULL,
                          XML_PARSE_NONET | XML_PARSE_NOBLANKS);
  if (xml_doc == NULL) {
    cmaper_nmap_xml_diag_setf(diag, "xml", "failed to parse nmap xml document");
    return CMAPER_ERR_PARSE;
  }

  rc = cmaper_nmap_xml_parse_doc(xml_doc, document, diag);
  xmlFreeDoc(xml_doc);
  return rc;
}

cmaper_err_t cmaper_nmap_xml_parse_file(const char *xml_path,
                                        cmaper_nmap_xml_document_t *document,
                                        cmaper_nmap_xml_diag_t *diag) {
  xmlDocPtr xml_doc = NULL;
  cmaper_err_t rc;

  if (xml_path == NULL || xml_path[0] == '\0' || document == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  xml_doc = xmlReadFile(xml_path, NULL, XML_PARSE_NONET | XML_PARSE_NOBLANKS);
  if (xml_doc == NULL) {
    cmaper_nmap_xml_diag_setf(diag, "xml", "failed to parse nmap xml document");
    return CMAPER_ERR_PARSE;
  }

  rc = cmaper_nmap_xml_parse_doc(xml_doc, document, diag);
  xmlFreeDoc(xml_doc);
  return rc;
}
