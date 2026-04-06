#include "cmaper/snapshot/internal/host_persist_internal.h"

#include "cmaper/snapshot/internal/device_internal.h"
#include "cmaper/snapshot/internal/host_children_internal.h"
#include "cmaper/snapshot/internal/host_observation_internal.h"
#include "cmaper/snapshot/internal/host_view_internal.h"
#include "cmaper/security/nmap_extract.h"
#include "cmaper/snapshot/security.h"

cmaper_err_t cmaper_snapshot_persist_merged_host(
    sqlite3 *db,
    sqlite3_int64 session_id,
    const cmaper_snapshot_merged_host_t *merged,
    cmaper_logger_t *logger
) {
    cmaper_snapshot_host_view_t host_view;
    cmaper_security_host_artifacts_t security_artifacts;
    sqlite3_int64 device_id = 0;
    sqlite3_int64 host_observation_id = 0;
    cmaper_err_t rc;

    if (db == NULL || merged == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_security_host_artifacts_init(&security_artifacts);

    rc = cmaper_snapshot_build_host_view(merged, &host_view);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    rc = cmaper_snapshot_resolve_device(
        db,
        session_id,
        host_view.ip,
        host_view.ip_type,
        host_view.mac != NULL ? host_view.mac->addr : NULL,
        host_view.mac != NULL ? host_view.mac->vendor : NULL,
        &device_id
    );
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    rc = cmaper_snapshot_upsert_host_observation(
        db,
        session_id,
        device_id,
        host_view.ip,
        host_view.ip_type,
        host_view.status,
        host_view.observation_source,
        host_view.hostname,
        host_view.mac != NULL ? host_view.mac->addr : NULL,
        host_view.mac != NULL ? host_view.mac->vendor : NULL,
        host_view.detail_xml_path,
        &host_observation_id
    );
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    rc = cmaper_snapshot_replace_host_children(db, host_observation_id, &host_view);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    rc = cmaper_security_extract_from_host_pair(
        host_view.primary,
        host_view.secondary,
        &security_artifacts
    );
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    rc = cmaper_snapshot_security_persist_host_artifacts(
        db,
        host_observation_id,
        &security_artifacts,
        logger
    );

cleanup:
    cmaper_security_host_artifacts_dispose(&security_artifacts);
    return rc;
}
