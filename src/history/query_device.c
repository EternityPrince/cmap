#include "cmaper/history/internal/query_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

cmaper_err_t cmaper_history_query_resolve_device(
    sqlite3 *db,
    const char *device_token,
    sqlite3_int64 *out_device_id
) {
    static const char *SQL =
        "SELECT d.id "
        "FROM devices d "
        "WHERE CAST(d.id AS TEXT)=?1 "
        "   OR lower(d.stable_key)=lower(?1) "
        "   OR lower(d.fallback_key)=lower(?1) "
        "   OR replace(lower(COALESCE(d.mac_address,'')),'-',':')=replace(lower(?1),'-',':') "
        "LIMIT 1;";
    sqlite3_stmt *stmt = NULL;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || device_token == NULL || device_token[0] == '\0' || out_device_id == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_device_id = 0;

    rc = cmaper_history_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_history_bind_text(stmt, 1, device_token);
    if (rc != CMAPER_OK) {
        cmaper_history_finalize(&stmt);
        return rc;
    }

    step_rc = sqlite3_step(stmt);
    if (step_rc == SQLITE_ROW) {
        *out_device_id = sqlite3_column_int64(stmt, 0);
        cmaper_history_finalize(&stmt);
        return CMAPER_OK;
    }
    if (step_rc == SQLITE_DONE) {
        cmaper_history_finalize(&stmt);
        return CMAPER_OK;
    }

    cmaper_history_finalize(&stmt);
    return CMAPER_ERR_IO;
}

cmaper_err_t cmaper_history_query_devices(
    sqlite3 *db,
    const cmaper_history_session_ref_t *session_ref,
    int limit,
    cmaper_history_devices_report_t *out_report
) {
    static const char *SQL_TOTAL =
        "SELECT COUNT(DISTINCT ho.device_id) "
        "FROM host_observations ho "
        "WHERE ho.session_id=?;";
    static const char *SQL_LIST =
        "SELECT CAST(d.id AS TEXT), d.stable_key, d.fallback_key, "
        "       COALESCE(d.mac_address,''), COALESCE(d.mac_vendor,''), "
        "       COALESCE((SELECT ho2.primary_ip "
        "                 FROM host_observations ho2 "
        "                 WHERE ho2.session_id=?1 AND ho2.device_id=d.id "
        "                 ORDER BY ho2.primary_ip ASC LIMIT 1), ''), "
        "       COALESCE((SELECT ho2.hostname_primary "
        "                 FROM host_observations ho2 "
        "                 WHERE ho2.session_id=?1 AND ho2.device_id=d.id "
        "                 ORDER BY ho2.primary_ip ASC LIMIT 1), ''), "
        "       COALESCE((SELECT ho2.status "
        "                 FROM host_observations ho2 "
        "                 WHERE ho2.session_id=?1 AND ho2.device_id=d.id "
        "                 ORDER BY ho2.primary_ip ASC LIMIT 1), ''), "
        "       COALESCE((SELECT COUNT(*) "
        "                 FROM host_observations ho3 "
        "                 WHERE ho3.session_id=?1 AND ho3.device_id=d.id), 0), "
        "       COALESCE((SELECT COUNT(*) "
        "                 FROM service_observations so "
        "                 JOIN host_observations ho ON ho.id=so.host_observation_id "
        "                 JOIN ports p ON p.id=so.port_id "
        "                 WHERE ho.session_id=?1 AND ho.device_id=d.id "
        "                   AND so.state='open' AND p.protocol='tcp'), 0), "
        "       COALESCE((SELECT COUNT(*) "
        "                 FROM vulnerability_findings vf "
        "                 JOIN host_observations ho ON ho.id=vf.host_observation_id "
        "                 WHERE ho.session_id=?1 AND ho.device_id=d.id AND vf.state='open'), 0), "
        "       COALESCE((SELECT COUNT(*) "
        "                 FROM vulnerability_findings vf "
        "                 JOIN host_observations ho ON ho.id=vf.host_observation_id "
        "                 WHERE ho.session_id=?1 AND ho.device_id=d.id AND vf.state='open' "
        "                   AND vf.severity IN ('high','critical')), 0), "
        "       COALESCE((SELECT COUNT(*) "
        "                 FROM management_surfaces ms "
        "                 JOIN host_observations ho ON ho.id=ms.host_observation_id "
        "                 WHERE ho.session_id=?1 AND ho.device_id=d.id), 0) "
        "FROM devices d "
        "WHERE EXISTS (SELECT 1 FROM host_observations ho WHERE ho.session_id=?1 AND ho.device_id=d.id) "
        "ORDER BY COALESCE(d.mac_address,''), d.id "
        "LIMIT ?2;";
    sqlite3_stmt *stmt_total = NULL;
    sqlite3_stmt *stmt_list = NULL;
    cmaper_history_buffer_t rows;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || session_ref == NULL || out_report == NULL) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    cmaper_history_devices_report_dispose(out_report);
    cmaper_history_devices_report_init(out_report);
    out_report->db_available = true;
    out_report->limit = limit > 0 ? limit : 50;
    cmaper_history_copy_string(
        out_report->session_id,
        sizeof(out_report->session_id),
        session_ref->session_uid
    );

    if (!session_ref->found || session_ref->id <= 0) {
        return CMAPER_OK;
    }
    out_report->session_found = true;

    rc = cmaper_history_buffer_init(&rows, sizeof(cmaper_history_device_row_t));
    if (rc != CMAPER_OK) {
        return rc;
    }

    rc = cmaper_history_prepare(db, SQL_TOTAL, &stmt_total);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int64(stmt_total, 1, session_ref->id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    step_rc = sqlite3_step(stmt_total);
    if (step_rc != SQLITE_ROW) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }
    out_report->total_devices = cmaper_history_column_size(stmt_total, 0);

    rc = cmaper_history_prepare(db, SQL_LIST, &stmt_list);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int64(stmt_list, 1, session_ref->id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int(stmt_list, 2, out_report->limit);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    while ((step_rc = sqlite3_step(stmt_list)) == SQLITE_ROW) {
        cmaper_history_device_row_t *row =
            (cmaper_history_device_row_t *) cmaper_history_buffer_push(&rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }

        cmaper_history_device_row_init(row);
        cmaper_history_copy_column_text(row->device_id, sizeof(row->device_id), stmt_list, 0);
        cmaper_history_copy_column_text(row->stable_key, sizeof(row->stable_key), stmt_list, 1);
        cmaper_history_copy_column_text(row->fallback_key, sizeof(row->fallback_key), stmt_list, 2);
        cmaper_history_copy_column_text(row->mac_address, sizeof(row->mac_address), stmt_list, 3);
        cmaper_history_copy_column_text(row->mac_vendor, sizeof(row->mac_vendor), stmt_list, 4);
        cmaper_history_copy_column_text(row->primary_ip, sizeof(row->primary_ip), stmt_list, 5);
        cmaper_history_copy_column_text(row->hostname, sizeof(row->hostname), stmt_list, 6);
        cmaper_history_copy_column_text(row->status, sizeof(row->status), stmt_list, 7);
        row->host_observations = cmaper_history_column_size(stmt_list, 8);
        row->open_tcp_ports = cmaper_history_column_size(stmt_list, 9);
        row->findings_open = cmaper_history_column_size(stmt_list, 10);
        row->findings_high_or_worse = cmaper_history_column_size(stmt_list, 11);
        row->management_surfaces = cmaper_history_column_size(stmt_list, 12);
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    if (rows.count > 1U) {
        qsort(rows.items, rows.count, sizeof(cmaper_history_device_row_t),
            cmaper_history_device_row_compare);
    }

    out_report->items = (cmaper_history_device_row_t *) rows.items;
    out_report->count = rows.count;
    out_report->truncated = out_report->total_devices > out_report->count;
    rows.items = NULL;
    rc = CMAPER_OK;

cleanup:
    cmaper_history_finalize(&stmt_total);
    cmaper_history_finalize(&stmt_list);
    cmaper_history_buffer_dispose(&rows);
    return rc;
}

cmaper_err_t cmaper_history_query_device(
    sqlite3 *db,
    const cmaper_history_session_ref_t *session_ref,
    sqlite3_int64 device_id,
    cmaper_history_device_report_t *out_report
) {
    static const char *SQL_DEVICE =
        "SELECT d.stable_key, d.fallback_key, COALESCE(d.mac_address,''), COALESCE(d.mac_vendor,''), "
        "       COALESCE(fs.session_uid,''), COALESCE(ls.session_uid,'') "
        "FROM devices d "
        "LEFT JOIN scan_sessions fs ON fs.id=d.first_seen_session_id "
        "LEFT JOIN scan_sessions ls ON ls.id=d.last_seen_session_id "
        "WHERE d.id=?;";
    static const char *SQL_SELECTED_OBS =
        "SELECT ho.primary_ip, COALESCE(ho.hostname_primary,''), COALESCE(ho.status,''), "
        "       COALESCE((SELECT COUNT(*) FROM service_observations so "
        "                 JOIN ports p ON p.id=so.port_id "
        "                 WHERE so.host_observation_id=ho.id AND so.state='open' AND p.protocol='tcp'), 0), "
        "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
        "                 WHERE vf.host_observation_id=ho.id AND vf.state='open'), 0), "
        "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
        "                 WHERE vf.host_observation_id=ho.id AND vf.state='open' "
        "                   AND vf.severity IN ('high','critical')), 0), "
        "       COALESCE((SELECT COUNT(*) FROM management_surfaces ms "
        "                 WHERE ms.host_observation_id=ho.id), 0) "
        "FROM host_observations ho "
        "WHERE ho.session_id=? AND ho.device_id=? "
        "ORDER BY ho.primary_ip ASC "
        "LIMIT 1;";
    static const char *SQL_IPS =
        "SELECT dip.ip_address, COALESCE(dip.address_type,''), dip.is_current, "
        "       COALESCE(fs.session_uid,''), COALESCE(ls.session_uid,'') "
        "FROM device_ip_addresses dip "
        "LEFT JOIN scan_sessions fs ON fs.id=dip.first_seen_session_id "
        "LEFT JOIN scan_sessions ls ON ls.id=dip.last_seen_session_id "
        "WHERE dip.device_id=? "
        "ORDER BY dip.is_current DESC, dip.ip_address ASC;";
    static const char *SQL_OBSERVATIONS =
        "SELECT s.session_uid, COALESCE(s.started_at,''), COALESCE(s.status,''), "
        "       ho.primary_ip, COALESCE(ho.hostname_primary,''), COALESCE(ho.status,''), "
        "       COALESCE((SELECT COUNT(*) FROM service_observations so "
        "                 JOIN ports p ON p.id=so.port_id "
        "                 WHERE so.host_observation_id=ho.id AND so.state='open' AND p.protocol='tcp'), 0), "
        "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
        "                 WHERE vf.host_observation_id=ho.id AND vf.state='open'), 0), "
        "       COALESCE((SELECT COUNT(*) FROM vulnerability_findings vf "
        "                 WHERE vf.host_observation_id=ho.id AND vf.state='open' "
        "                   AND vf.severity IN ('high','critical')), 0), "
        "       COALESCE((SELECT COUNT(*) FROM management_surfaces ms "
        "                 WHERE ms.host_observation_id=ho.id), 0) "
        "FROM host_observations ho "
        "JOIN scan_sessions s ON s.id=ho.session_id "
        "WHERE ho.device_id=? "
        "ORDER BY s.started_at DESC, s.id DESC;";
    sqlite3_stmt *stmt_device = NULL;
    sqlite3_stmt *stmt_selected = NULL;
    sqlite3_stmt *stmt_ips = NULL;
    sqlite3_stmt *stmt_observations = NULL;
    cmaper_history_buffer_t ip_rows;
    cmaper_history_buffer_t observation_rows;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || session_ref == NULL || out_report == NULL || device_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    memset(&ip_rows, 0, sizeof(ip_rows));
    memset(&observation_rows, 0, sizeof(observation_rows));

    cmaper_history_device_report_dispose(out_report);
    cmaper_history_device_report_init(out_report);
    out_report->db_available = true;
    cmaper_history_copy_string(out_report->session_id, sizeof(out_report->session_id),
        session_ref->session_uid);
    (void) snprintf(out_report->device_id, sizeof(out_report->device_id), "%lld",
        (long long) device_id);

    if (!session_ref->found || session_ref->id <= 0) {
        return CMAPER_OK;
    }
    out_report->session_found = true;

    rc = cmaper_history_prepare(db, SQL_DEVICE, &stmt_device);
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_history_bind_int64(stmt_device, 1, device_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    step_rc = sqlite3_step(stmt_device);
    if (step_rc == SQLITE_DONE) {
        rc = CMAPER_OK;
        goto cleanup;
    }
    if (step_rc != SQLITE_ROW) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    out_report->found = true;
    cmaper_history_copy_column_text(out_report->stable_key, sizeof(out_report->stable_key), stmt_device, 0);
    cmaper_history_copy_column_text(out_report->fallback_key, sizeof(out_report->fallback_key), stmt_device, 1);
    cmaper_history_copy_column_text(out_report->mac_address, sizeof(out_report->mac_address), stmt_device, 2);
    cmaper_history_copy_column_text(out_report->mac_vendor, sizeof(out_report->mac_vendor), stmt_device, 3);
    cmaper_history_copy_column_text(
        out_report->first_seen_session_id,
        sizeof(out_report->first_seen_session_id),
        stmt_device,
        4
    );
    cmaper_history_copy_column_text(
        out_report->last_seen_session_id,
        sizeof(out_report->last_seen_session_id),
        stmt_device,
        5
    );

    rc = cmaper_history_prepare(db, SQL_SELECTED_OBS, &stmt_selected);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int64(stmt_selected, 1, session_ref->id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int64(stmt_selected, 2, device_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    step_rc = sqlite3_step(stmt_selected);
    if (step_rc == SQLITE_ROW) {
        out_report->selected_observation_found = true;
        cmaper_history_copy_column_text(
            out_report->selected_primary_ip,
            sizeof(out_report->selected_primary_ip),
            stmt_selected,
            0
        );
        cmaper_history_copy_column_text(
            out_report->selected_hostname,
            sizeof(out_report->selected_hostname),
            stmt_selected,
            1
        );
        cmaper_history_copy_column_text(
            out_report->selected_status,
            sizeof(out_report->selected_status),
            stmt_selected,
            2
        );
        out_report->selected_open_tcp_ports = cmaper_history_column_size(stmt_selected, 3);
        out_report->selected_findings_open = cmaper_history_column_size(stmt_selected, 4);
        out_report->selected_findings_high_or_worse = cmaper_history_column_size(stmt_selected, 5);
        out_report->selected_management_surfaces = cmaper_history_column_size(stmt_selected, 6);
    } else if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    rc = cmaper_history_buffer_init(&ip_rows, sizeof(cmaper_history_device_ip_row_t));
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_prepare(db, SQL_IPS, &stmt_ips);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int64(stmt_ips, 1, device_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    while ((step_rc = sqlite3_step(stmt_ips)) == SQLITE_ROW) {
        cmaper_history_device_ip_row_t *row =
            (cmaper_history_device_ip_row_t *) cmaper_history_buffer_push(&ip_rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        cmaper_history_device_ip_row_init(row);
        cmaper_history_copy_column_text(row->ip_address, sizeof(row->ip_address), stmt_ips, 0);
        cmaper_history_copy_column_text(row->address_type, sizeof(row->address_type), stmt_ips, 1);
        row->is_current = sqlite3_column_int(stmt_ips, 2) != 0;
        cmaper_history_copy_column_text(
            row->first_seen_session_id,
            sizeof(row->first_seen_session_id),
            stmt_ips,
            3
        );
        cmaper_history_copy_column_text(
            row->last_seen_session_id,
            sizeof(row->last_seen_session_id),
            stmt_ips,
            4
        );
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    rc = cmaper_history_buffer_init(
        &observation_rows,
        sizeof(cmaper_history_device_observation_row_t)
    );
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_prepare(db, SQL_OBSERVATIONS, &stmt_observations);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int64(stmt_observations, 1, device_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    while ((step_rc = sqlite3_step(stmt_observations)) == SQLITE_ROW) {
        cmaper_history_device_observation_row_t *row =
            (cmaper_history_device_observation_row_t *) cmaper_history_buffer_push(&observation_rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        cmaper_history_device_observation_row_init(row);
        cmaper_history_copy_column_text(row->session_id, sizeof(row->session_id), stmt_observations, 0);
        cmaper_history_copy_column_text(row->started_at, sizeof(row->started_at), stmt_observations, 1);
        cmaper_history_copy_column_text(row->status, sizeof(row->status), stmt_observations, 2);
        cmaper_history_copy_column_text(row->primary_ip, sizeof(row->primary_ip), stmt_observations, 3);
        cmaper_history_copy_column_text(row->hostname, sizeof(row->hostname), stmt_observations, 4);
        cmaper_history_copy_column_text(row->host_status, sizeof(row->host_status), stmt_observations, 5);
        row->open_tcp_ports = cmaper_history_column_size(stmt_observations, 6);
        row->findings_open = cmaper_history_column_size(stmt_observations, 7);
        row->findings_high_or_worse = cmaper_history_column_size(stmt_observations, 8);
        row->management_surfaces = cmaper_history_column_size(stmt_observations, 9);
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    if (ip_rows.count > 1U) {
        qsort(ip_rows.items, ip_rows.count, sizeof(cmaper_history_device_ip_row_t),
            cmaper_history_device_ip_row_compare);
    }

    out_report->ip_addresses = (cmaper_history_device_ip_row_t *) ip_rows.items;
    out_report->ip_address_count = ip_rows.count;
    out_report->observations = (cmaper_history_device_observation_row_t *) observation_rows.items;
    out_report->observation_count = observation_rows.count;
    ip_rows.items = NULL;
    observation_rows.items = NULL;
    rc = CMAPER_OK;

cleanup:
    cmaper_history_finalize(&stmt_device);
    cmaper_history_finalize(&stmt_selected);
    cmaper_history_finalize(&stmt_ips);
    cmaper_history_finalize(&stmt_observations);
    cmaper_history_buffer_dispose(&ip_rows);
    cmaper_history_buffer_dispose(&observation_rows);
    return rc;
}

static cmaper_err_t cmaper_history_load_ports(
    sqlite3 *db,
    sqlite3_int64 host_observation_id,
    cmaper_history_host_snapshot_t *snapshot
) {
    static const char *SQL =
        "SELECT p.protocol, p.port_number "
        "FROM service_observations so "
        "JOIN ports p ON p.id=so.port_id "
        "WHERE so.host_observation_id=? AND so.state='open' "
        "ORDER BY p.protocol ASC, p.port_number ASC;";
    sqlite3_stmt *stmt = NULL;
    cmaper_history_buffer_t rows;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || snapshot == NULL || host_observation_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_history_buffer_init(&rows, sizeof(cmaper_history_port_signal_t));
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_history_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int64(stmt, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        cmaper_history_port_signal_t *row =
            (cmaper_history_port_signal_t *) cmaper_history_buffer_push(&rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        cmaper_history_copy_column_text(row->protocol, sizeof(row->protocol), stmt, 0);
        row->port = sqlite3_column_int(stmt, 1);
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    snapshot->ports = (cmaper_history_port_signal_t *) rows.items;
    snapshot->port_count = rows.count;
    rows.items = NULL;
    rc = CMAPER_OK;

cleanup:
    cmaper_history_finalize(&stmt);
    cmaper_history_buffer_dispose(&rows);
    return rc;
}

static cmaper_err_t cmaper_history_load_fingerprints(
    sqlite3 *db,
    sqlite3_int64 host_observation_id,
    cmaper_history_host_snapshot_t *snapshot
) {
    static const char *SQL =
        "SELECT x.kind, x.fingerprint, COALESCE(x.protocol,''), COALESCE(x.port_number,0) "
        "FROM ("
        "  SELECT 'tls' AS kind, tf.fingerprint AS fingerprint, p.protocol AS protocol, p.port_number AS port_number "
        "  FROM tls_fingerprints tf "
        "  LEFT JOIN service_observations so ON so.id=tf.service_observation_id "
        "  LEFT JOIN ports p ON p.id=so.port_id "
        "  WHERE tf.host_observation_id=?1 "
        "  UNION ALL "
        "  SELECT 'ssh', sf.fingerprint, p.protocol, p.port_number "
        "  FROM ssh_fingerprints sf "
        "  LEFT JOIN service_observations so ON so.id=sf.service_observation_id "
        "  LEFT JOIN ports p ON p.id=so.port_id "
        "  WHERE sf.host_observation_id=?1 "
        "  UNION ALL "
        "  SELECT 'http', hf.fingerprint, p.protocol, p.port_number "
        "  FROM http_fingerprints hf "
        "  LEFT JOIN service_observations so ON so.id=hf.service_observation_id "
        "  LEFT JOIN ports p ON p.id=so.port_id "
        "  WHERE hf.host_observation_id=?1 "
        "  UNION ALL "
        "  SELECT 'smb', bf.fingerprint, p.protocol, p.port_number "
        "  FROM smb_fingerprints bf "
        "  LEFT JOIN service_observations so ON so.id=bf.service_observation_id "
        "  LEFT JOIN ports p ON p.id=so.port_id "
        "  WHERE bf.host_observation_id=?1 "
        ") AS x "
        "WHERE x.fingerprint IS NOT NULL AND x.fingerprint<>'' "
        "ORDER BY x.kind ASC, x.protocol ASC, x.port_number ASC, x.fingerprint ASC;";
    sqlite3_stmt *stmt = NULL;
    cmaper_history_buffer_t rows;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || snapshot == NULL || host_observation_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_history_buffer_init(&rows, sizeof(cmaper_history_fingerprint_signal_t));
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_history_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int64(stmt, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        cmaper_history_fingerprint_signal_t *row =
            (cmaper_history_fingerprint_signal_t *) cmaper_history_buffer_push(&rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        cmaper_history_copy_column_text(row->kind, sizeof(row->kind), stmt, 0);
        cmaper_history_copy_column_text(row->value, sizeof(row->value), stmt, 1);
        cmaper_history_copy_column_text(row->protocol, sizeof(row->protocol), stmt, 2);
        row->port = sqlite3_column_int(stmt, 3);
        row->has_service_context = row->port > 0 && row->protocol[0] != '\0';
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    snapshot->fingerprints = (cmaper_history_fingerprint_signal_t *) rows.items;
    snapshot->fingerprint_count = rows.count;
    rows.items = NULL;
    rc = CMAPER_OK;

cleanup:
    cmaper_history_finalize(&stmt);
    cmaper_history_buffer_dispose(&rows);
    return rc;
}

static cmaper_err_t cmaper_history_load_findings(
    sqlite3 *db,
    sqlite3_int64 host_observation_id,
    cmaper_history_host_snapshot_t *snapshot
) {
    static const char *SQL =
        "SELECT COALESCE(vf.finding_key,''), COALESCE(vf.severity,''), COALESCE(vf.state,''), "
        "       COALESCE(vf.title,''), COALESCE(p.protocol,''), COALESCE(p.port_number,0) "
        "FROM vulnerability_findings vf "
        "LEFT JOIN service_observations so ON so.id=vf.service_observation_id "
        "LEFT JOIN ports p ON p.id=so.port_id "
        "WHERE vf.host_observation_id=? "
        "ORDER BY vf.finding_key ASC, p.protocol ASC, p.port_number ASC;";
    sqlite3_stmt *stmt = NULL;
    cmaper_history_buffer_t rows;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || snapshot == NULL || host_observation_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_history_buffer_init(&rows, sizeof(cmaper_history_finding_signal_t));
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_history_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int64(stmt, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        cmaper_history_finding_signal_t *row =
            (cmaper_history_finding_signal_t *) cmaper_history_buffer_push(&rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        cmaper_history_copy_column_text(row->key, sizeof(row->key), stmt, 0);
        cmaper_history_copy_column_text(row->severity, sizeof(row->severity), stmt, 1);
        cmaper_history_copy_column_text(row->state, sizeof(row->state), stmt, 2);
        cmaper_history_copy_column_text(row->title, sizeof(row->title), stmt, 3);
        cmaper_history_copy_column_text(row->protocol, sizeof(row->protocol), stmt, 4);
        row->port = sqlite3_column_int(stmt, 5);
        row->has_service_context = row->port > 0 && row->protocol[0] != '\0';
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    snapshot->findings = (cmaper_history_finding_signal_t *) rows.items;
    snapshot->finding_count = rows.count;
    rows.items = NULL;
    rc = CMAPER_OK;

cleanup:
    cmaper_history_finalize(&stmt);
    cmaper_history_buffer_dispose(&rows);
    return rc;
}

static cmaper_err_t cmaper_history_load_surfaces(
    sqlite3 *db,
    sqlite3_int64 host_observation_id,
    cmaper_history_host_snapshot_t *snapshot
) {
    static const char *SQL =
        "SELECT COALESCE(ms.surface_type,''), COALESCE(ms.detail,''), "
        "       COALESCE(p.protocol,''), COALESCE(p.port_number,0) "
        "FROM management_surfaces ms "
        "LEFT JOIN service_observations so ON so.id=ms.service_observation_id "
        "LEFT JOIN ports p ON p.id=so.port_id "
        "WHERE ms.host_observation_id=? "
        "ORDER BY ms.surface_type ASC, p.protocol ASC, p.port_number ASC;";
    sqlite3_stmt *stmt = NULL;
    cmaper_history_buffer_t rows;
    cmaper_err_t rc;
    int step_rc;

    if (db == NULL || snapshot == NULL || host_observation_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    rc = cmaper_history_buffer_init(&rows, sizeof(cmaper_history_surface_signal_t));
    if (rc != CMAPER_OK) {
        return rc;
    }
    rc = cmaper_history_prepare(db, SQL, &stmt);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int64(stmt, 1, host_observation_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    while ((step_rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        cmaper_history_surface_signal_t *row =
            (cmaper_history_surface_signal_t *) cmaper_history_buffer_push(&rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        cmaper_history_copy_column_text(row->type, sizeof(row->type), stmt, 0);
        cmaper_history_copy_column_text(row->detail, sizeof(row->detail), stmt, 1);
        cmaper_history_copy_column_text(row->protocol, sizeof(row->protocol), stmt, 2);
        row->port = sqlite3_column_int(stmt, 3);
        row->has_service_context = row->port > 0 && row->protocol[0] != '\0';
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    snapshot->surfaces = (cmaper_history_surface_signal_t *) rows.items;
    snapshot->surface_count = rows.count;
    rows.items = NULL;
    rc = CMAPER_OK;

cleanup:
    cmaper_history_finalize(&stmt);
    cmaper_history_buffer_dispose(&rows);
    return rc;
}

cmaper_err_t cmaper_history_query_host_snapshots(
    sqlite3 *db,
    sqlite3_int64 session_id,
    cmaper_history_host_snapshot_t **out_items,
    size_t *out_count
) {
    static const char *SQL_HOSTS =
        "SELECT ho.id, ho.device_id, CAST(ho.device_id AS TEXT), ho.primary_ip, "
        "       COALESCE(ho.mac_address,''), COALESCE(ho.hostname_primary,''), COALESCE(ho.status,'') "
        "FROM host_observations ho "
        "WHERE ho.session_id=? "
        "ORDER BY ho.primary_ip ASC, ho.id ASC;";
    sqlite3_stmt *stmt_hosts = NULL;
    cmaper_history_buffer_t rows;
    cmaper_err_t rc;
    int step_rc;
    size_t i;

    if (db == NULL || out_items == NULL || out_count == NULL || session_id <= 0) {
        return CMAPER_ERR_INVALID_ARGUMENT;
    }

    *out_items = NULL;
    *out_count = 0;

    rc = cmaper_history_buffer_init(&rows, sizeof(cmaper_history_host_snapshot_t));
    if (rc != CMAPER_OK) {
        return rc;
    }

    rc = cmaper_history_prepare(db, SQL_HOSTS, &stmt_hosts);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }
    rc = cmaper_history_bind_int64(stmt_hosts, 1, session_id);
    if (rc != CMAPER_OK) {
        goto cleanup;
    }

    while ((step_rc = sqlite3_step(stmt_hosts)) == SQLITE_ROW) {
        cmaper_history_host_snapshot_t *row =
            (cmaper_history_host_snapshot_t *) cmaper_history_buffer_push(&rows);
        if (row == NULL) {
            rc = CMAPER_ERR_OOM;
            goto cleanup;
        }
        cmaper_history_host_snapshot_init(row);
        row->host_observation_id = sqlite3_column_int64(stmt_hosts, 0);
        row->device_db_id = sqlite3_column_int64(stmt_hosts, 1);
        cmaper_history_copy_column_text(row->device_id, sizeof(row->device_id), stmt_hosts, 2);
        cmaper_history_copy_column_text(row->primary_ip, sizeof(row->primary_ip), stmt_hosts, 3);
        cmaper_history_copy_column_text(row->mac_address, sizeof(row->mac_address), stmt_hosts, 4);
        cmaper_history_copy_column_text(row->hostname, sizeof(row->hostname), stmt_hosts, 5);
        cmaper_history_copy_column_text(row->status, sizeof(row->status), stmt_hosts, 6);
    }
    if (step_rc != SQLITE_DONE) {
        rc = CMAPER_ERR_IO;
        goto cleanup;
    }

    for (i = 0; i < rows.count; ++i) {
        cmaper_history_host_snapshot_t *snapshot =
            &((cmaper_history_host_snapshot_t *) rows.items)[i];
        rc = cmaper_history_load_ports(db, snapshot->host_observation_id, snapshot);
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
        rc = cmaper_history_load_fingerprints(db, snapshot->host_observation_id, snapshot);
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
        rc = cmaper_history_load_findings(db, snapshot->host_observation_id, snapshot);
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
        rc = cmaper_history_load_surfaces(db, snapshot->host_observation_id, snapshot);
        if (rc != CMAPER_OK) {
            goto cleanup;
        }
    }

    if (rows.count > 1U) {
        qsort(rows.items, rows.count, sizeof(cmaper_history_host_snapshot_t),
            cmaper_history_snapshot_compare);
    }

    *out_items = (cmaper_history_host_snapshot_t *) rows.items;
    *out_count = rows.count;
    rows.items = NULL;
    rc = CMAPER_OK;

cleanup:
    cmaper_history_finalize(&stmt_hosts);
    if (rc != CMAPER_OK && rows.items != NULL) {
        cmaper_history_host_snapshots_dispose((cmaper_history_host_snapshot_t *) rows.items, rows.count);
        rows.items = NULL;
    }
    cmaper_history_buffer_dispose(&rows);
    return rc;
}
