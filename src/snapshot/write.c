#include "cmaper/snapshot/write.h"

#include "cmaper/snapshot/internal/host_persist_internal.h"
#include "cmaper/snapshot/internal/merge_internal.h"
#include "cmaper/snapshot/internal/session_internal.h"
#include "cmaper/snapshot/internal/sqlite_internal.h"
#include "cmaper/scan/nmap_xml_parse.h"

cmaper_err_t cmaper_snapshot_write_scan_data(
    sqlite3 *db,
    const cmaper_snapshot_write_request_t *request,
    cmaper_logger_t *logger
) {
    cmaper_nmap_xml_document_t discovery_doc;
    cmaper_nmap_xml_diag_t discovery_diag;
    cmaper_snapshot_detail_doc_t *detail_docs = NULL;
    size_t detail_doc_count = 0;
    cmaper_snapshot_merged_host_t *merged_hosts = NULL;
    size_t merged_host_count = 0;
    sqlite3_int64 session_id = 0;
    size_t i;
    cmaper_err_t rc;

    if (db == NULL || request == NULL || request->session_uid == NULL
        || request->plan == NULL || request->scan_result == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    if ((request->scan_result->discovery_xml == NULL || request->scan_result->discovery_xml_size == 0)
        && request->scan_result->discovery_xml_path[0] == '\0') {
        return CMAPER_ERR_PARSE;
    }

    rc = cmaper_snapshot_get_session_id(db, request->session_uid, &session_id);
    if (rc != CMAPER_OK || session_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_nmap_xml_document_init(&discovery_doc);
    cmaper_nmap_xml_diag_clear(&discovery_diag);
    if (request->scan_result->discovery_xml != NULL && request->scan_result->discovery_xml_size > 0) {
        rc = cmaper_nmap_xml_parse_memory(
            request->scan_result->discovery_xml,
            request->scan_result->discovery_xml_size,
            &discovery_doc,
            &discovery_diag
        );
    } else {
        rc = cmaper_nmap_xml_parse_file(
            request->scan_result->discovery_xml_path,
            &discovery_doc,
            &discovery_diag
        );
    }
    if (rc != CMAPER_OK) {
        cmaper_log(
            logger,
            CMAPER_LOG_FAIL,
            "snapshot/write: discovery xml parse failed: %s",
            discovery_diag.message[0] != '\0' ? discovery_diag.message : "parse error"
        );
        cmaper_nmap_xml_document_dispose(&discovery_doc);
        return CMAPER_ERR_PARSE;
    }

    rc = cmaper_snapshot_build_detail_docs(
        request->scan_result,
        &detail_docs,
        &detail_doc_count,
        logger
    );
    if (rc != CMAPER_OK) {
        cmaper_nmap_xml_document_dispose(&discovery_doc);
        return rc;
    }

    rc = cmaper_snapshot_build_merged_hosts(
        &discovery_doc,
        detail_docs,
        detail_doc_count,
        &merged_hosts,
        &merged_host_count
    );
    if (rc != CMAPER_OK) {
        cmaper_snapshot_detail_docs_dispose(detail_docs, detail_doc_count);
        cmaper_nmap_xml_document_dispose(&discovery_doc);
        return rc;
    }

    rc = cmaper_snapshot_sqlite_exec(db, "BEGIN IMMEDIATE TRANSACTION;");
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    rc = cmaper_snapshot_upsert_session_networks(db, session_id, request->plan->target);
    if (rc != CMAPER_OK) {
        goto rollback;
    }

    for (i = 0; i < merged_host_count; ++i) {
        rc = cmaper_snapshot_persist_merged_host(db, session_id, &merged_hosts[i], logger);
        if (rc != CMAPER_OK) {
            goto rollback;
        }
    }

    rc = cmaper_snapshot_sqlite_exec(db, "COMMIT;");
    if (rc != CMAPER_OK) {
        goto rollback;
    }

    cmaper_log(
        logger,
        CMAPER_LOG_OK,
        "snapshot/write: persisted %zu merged host observations",
        merged_host_count
    );

    rc = CMAPER_OK;
    goto cleanup;

rollback:
    sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL);

cleanup:
    cmaper_snapshot_merged_hosts_dispose(merged_hosts);
    cmaper_snapshot_detail_docs_dispose(detail_docs, detail_doc_count);
    cmaper_nmap_xml_document_dispose(&discovery_doc);
    return rc;
}
