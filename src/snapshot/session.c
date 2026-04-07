#include "cmaper/snapshot/internal/session_internal.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "cmaper/snapshot/internal/sqlite_internal.h"

#define CMAPER_SNAPSHOT_NETWORK_CAP 256

static bool cmaper_snapshot_is_ipv4(const char *ip) {
  struct in_addr addr;
  return ip != NULL && inet_pton(AF_INET, ip, &addr) == 1;
}

static bool cmaper_snapshot_is_ipv6(const char *ip) {
  struct in6_addr addr;
  return ip != NULL && inet_pton(AF_INET6, ip, &addr) == 1;
}

static void cmaper_snapshot_make_network_token(const char *token, char *out,
                                               size_t out_cap) {
  if (out == NULL || out_cap == 0) {
    return;
  }

  out[0] = '\0';
  if (token == NULL || token[0] == '\0') {
    return;
  }

  if (strchr(token, '/') != NULL) {
    snprintf(out, out_cap, "%s", token);
    return;
  }

  if (cmaper_snapshot_is_ipv4(token)) {
    snprintf(out, out_cap, "%s/32", token);
    return;
  }

  if (cmaper_snapshot_is_ipv6(token)) {
    snprintf(out, out_cap, "%s/128", token);
    return;
  }

  snprintf(out, out_cap, "%s", token);
}

static cmaper_err_t cmaper_snapshot_upsert_network(sqlite3 *db,
                                                   sqlite3_int64 session_id,
                                                   const char *network_token) {
  static const char *SQL_NETWORK =
      "INSERT INTO networks(cidr, first_seen_session_id, last_seen_session_id) "
      "VALUES(?, ?, ?) "
      "ON CONFLICT(cidr) DO UPDATE SET "
      "last_seen_session_id=excluded.last_seen_session_id;";
  static const char *SQL_NETWORK_ID = "SELECT id FROM networks WHERE cidr=?;";
  static const char *SQL_LINK =
      "INSERT OR IGNORE INTO session_networks(session_id, network_id) "
      "VALUES(?, ?);";
  sqlite3_stmt *stmt_network = NULL;
  sqlite3_stmt *stmt_network_id = NULL;
  sqlite3_stmt *stmt_link = NULL;
  sqlite3_int64 network_id = 0;
  cmaper_err_t rc = CMAPER_OK;

  if (db == NULL || network_token == NULL || network_token[0] == '\0') {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  rc = cmaper_snapshot_sqlite_prepare(db, SQL_NETWORK, &stmt_network);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text(stmt_network, 1, network_token);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int64(stmt_network, 2, session_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int64(stmt_network, 3, session_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_step_done(stmt_network);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  rc = cmaper_snapshot_sqlite_prepare(db, SQL_NETWORK_ID, &stmt_network_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_text(stmt_network_id, 1, network_token);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_step_row(stmt_network_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  network_id = sqlite3_column_int64(stmt_network_id, 0);

  rc = cmaper_snapshot_sqlite_prepare(db, SQL_LINK, &stmt_link);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int64(stmt_link, 1, session_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_bind_int64(stmt_link, 2, network_id);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }
  rc = cmaper_snapshot_sqlite_step_done(stmt_link);

cleanup:
  cmaper_snapshot_sqlite_finalize(&stmt_network);
  cmaper_snapshot_sqlite_finalize(&stmt_network_id);
  cmaper_snapshot_sqlite_finalize(&stmt_link);
  return rc;
}

cmaper_err_t cmaper_snapshot_get_session_id(sqlite3 *db,
                                            const char *session_uid,
                                            sqlite3_int64 *out_session_id) {
  static const char *SQL = "SELECT id FROM scan_sessions WHERE session_uid=?;";
  sqlite3_stmt *stmt = NULL;
  cmaper_err_t rc;

  if (db == NULL || session_uid == NULL || out_session_id == NULL) {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  *out_session_id = 0;

  rc = cmaper_snapshot_sqlite_prepare(db, SQL, &stmt);
  if (rc != CMAPER_OK) {
    return rc;
  }

  rc = cmaper_snapshot_sqlite_bind_text(stmt, 1, session_uid);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  rc = cmaper_snapshot_sqlite_step_row(stmt);
  if (rc != CMAPER_OK) {
    goto cleanup;
  }

  *out_session_id = sqlite3_column_int64(stmt, 0);
  rc = CMAPER_OK;

cleanup:
  cmaper_snapshot_sqlite_finalize(&stmt);
  return rc;
}

cmaper_err_t
cmaper_snapshot_upsert_session_networks(sqlite3 *db, sqlite3_int64 session_id,
                                        const char *target_expression) {
  size_t i = 0;
  char token[CMAPER_SNAPSHOT_NETWORK_CAP];
  size_t token_len = 0;
  cmaper_err_t rc = CMAPER_OK;

  if (db == NULL || target_expression == NULL || target_expression[0] == '\0') {
    return CMAPER_ERR_INVALID_ARGUMENT;
  }

  while (true) {
    char ch = target_expression[i];
    bool is_delim = (ch == '\0' || ch == ',' || isspace((unsigned char)ch));

    if (!is_delim && token_len + 1U < sizeof(token)) {
      token[token_len++] = ch;
    }

    if (is_delim && token_len > 0) {
      char network_token[CMAPER_SNAPSHOT_NETWORK_CAP];
      token[token_len] = '\0';
      cmaper_snapshot_make_network_token(token, network_token,
                                         sizeof(network_token));
      if (network_token[0] != '\0') {
        rc = cmaper_snapshot_upsert_network(db, session_id, network_token);
        if (rc != CMAPER_OK) {
          return rc;
        }
      }
      token_len = 0;
    }

    if (ch == '\0') {
      break;
    }

    i += 1U;
  }

  return CMAPER_OK;
}
