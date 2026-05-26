#include "edge/buffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* Schema — created on first init */
static const char *SCHEMA =
    "CREATE TABLE IF NOT EXISTS events ("
    "  id       INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  topic    TEXT    NOT NULL,"
    "  payload  BLOB    NOT NULL,"
    "  ts       INTEGER NOT NULL DEFAULT (unixepoch()),"
    "  flushed  INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_events_flushed ON events(flushed, ts);";

static const char *PRAGMA_WAL =
    "PRAGMA journal_mode=WAL;"
    "PRAGMA synchronous=NORMAL;"    /* safe with WAL; faster than FULL */
    "PRAGMA foreign_keys=ON;";

int buffer_init(buffer_t *buf, const char *db_path) {
    if (!buf || !db_path) return -1;
    memset(buf, 0, sizeof(*buf));

    int rc = sqlite3_open(db_path, &buf->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[BUFFER] sqlite3_open(%s): %s\n",
                db_path, sqlite3_errmsg(buf->db));
        return -1;
    }

    /* Apply PRAGMAs and schema in one exec */
    char *errmsg = NULL;
    rc = sqlite3_exec(buf->db, PRAGMA_WAL, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[BUFFER] PRAGMA: %s\n", errmsg);
        sqlite3_free(errmsg);
        return -1;
    }

    rc = sqlite3_exec(buf->db, SCHEMA, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[BUFFER] schema: %s\n", errmsg);
        sqlite3_free(errmsg);
        return -1;
    }

    fprintf(stderr, "[BUFFER] initialised: %s\n", db_path);
    return 0;
}

int buffer_event_insert(buffer_t      *buf,
                        const char    *topic,
                        const uint8_t *payload,
                        size_t         payload_len) {
    if (!buf || !buf->db || !topic || !payload) return -1;

    sqlite3_stmt *stmt = NULL;
    const char   *sql  =
        "INSERT INTO events (topic, payload) VALUES (?, ?);";

    int rc = sqlite3_prepare_v2(buf->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[BUFFER] prepare insert: %s\n", sqlite3_errmsg(buf->db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, topic, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, payload, (int)payload_len, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[BUFFER] insert: %s\n", sqlite3_errmsg(buf->db));
        return -1;
    }
    return 0;
}

int buffer_events_read_unflushed(buffer_t       *buf,
                                  buffer_event_t *events,
                                  int             max_events) {
    if (!buf || !buf->db || !events || max_events <= 0) return -1;

    const char *sql =
        "SELECT id, topic, payload, ts FROM events "
        "WHERE flushed = 0 ORDER BY ts ASC LIMIT ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(buf->db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[BUFFER] prepare read: %s\n", sqlite3_errmsg(buf->db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, max_events);

    int count = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && count < max_events) {
        buffer_event_t *ev = &events[count];

        ev->id          = sqlite3_column_int64(stmt, 0);
        ev->ts          = sqlite3_column_int64(stmt, 3);
        ev->payload     = NULL;
        ev->payload_len = 0;

        /* topic */
        const char *t = (const char *)sqlite3_column_text(stmt, 1);
        if (t) snprintf(ev->topic, BUFFER_MAX_TOPIC, "%s", t);

        /* payload — copy out of SQLite's buffer */
        int blob_len = sqlite3_column_bytes(stmt, 2);
        if (blob_len > 0) {
            const void *blob = sqlite3_column_blob(stmt, 2);
            ev->payload = malloc((size_t)blob_len);
            if (!ev->payload) {
                fprintf(stderr, "[BUFFER] OOM reading payload\n");
                break;
            }
            memcpy(ev->payload, blob, (size_t)blob_len);
            ev->payload_len = (size_t)blob_len;
        }

        count++;
    }

    sqlite3_finalize(stmt);
    return (rc == SQLITE_ROW || rc == SQLITE_DONE) ? count : -1;
}

int buffer_events_mark_flushed(buffer_t      *buf,
                                const int64_t *ids,
                                int            count) {
    if (!buf || !buf->db || !ids || count <= 0) return -1;

    /* Wrap in a transaction for efficiency */
    char *errmsg = NULL;
    sqlite3_exec(buf->db, "BEGIN;", NULL, NULL, &errmsg);
    sqlite3_free(errmsg);

    sqlite3_stmt *stmt = NULL;
    const char   *sql  = "UPDATE events SET flushed = 1 WHERE id = ?;";

    sqlite3_prepare_v2(buf->db, sql, -1, &stmt, NULL);

    for (int i = 0; i < count; i++) {
        sqlite3_reset(stmt);
        sqlite3_bind_int64(stmt, 1, ids[i]);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);

    errmsg = NULL;
    int rc = sqlite3_exec(buf->db, "COMMIT;", NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[BUFFER] commit mark_flushed: %s\n", errmsg);
        sqlite3_free(errmsg);
        return -1;
    }

    return 0;
}

void buffer_events_free(buffer_event_t *events, int count) {
    if (!events) return;
    for (int i = 0; i < count; i++) {
        free(events[i].payload);
        events[i].payload = NULL;
    }
}

void buffer_close(buffer_t *buf) {
    if (!buf) return;
    if (buf->db) {
        sqlite3_close(buf->db);
        buf->db = NULL;
    }
}
