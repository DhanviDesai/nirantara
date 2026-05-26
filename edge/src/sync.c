#include "edge/sync.h"
#include "edge/buffer.h"

#include <libpq-fe.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdatomic.h>
#include <time.h>

static pthread_t    g_thread;
static sync_ctx_t  *g_ctx = NULL;

/* ── Postgres upsert ─────────────────────────────────────────────────────── */

/*
 * Upsert SQL:
 *   ON CONFLICT (device_id, topic, ts) DO NOTHING
 * This makes every flush idempotent — safe to retry after a failed flush.
 *
 * The device_id is extracted from the MQTT topic: game/<device_id>/...
 */

static const char *UPSERT_SQL =
    "INSERT INTO game_events (device_id, topic, payload, ts, edge_node) "
    "VALUES ($1, $2, $3, $4, $5) "
    "ON CONFLICT (device_id, topic, ts) DO NOTHING;";

static char *extract_device_id(const char *topic, char *out, size_t out_len) {
    /* Topic format: game/<device_id>/events or similar */
    const char *p = strchr(topic, '/');
    if (!p) { snprintf(out, out_len, "unknown"); return out; }
    p++;
    const char *end = strchr(p, '/');
    size_t len = end ? (size_t)(end - p) : strlen(p);
    if (len >= out_len) len = out_len - 1;
    memcpy(out, p, len);
    out[len] = '\0';
    return out;
}

static int pg_flush(sync_ctx_t     *ctx,
                    buffer_t       *read_buf,
                    buffer_event_t *events,
                    int             count) {
    PGconn *conn = PQconnectdb(ctx->pg_connstr);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[SYNC] pg connect failed: %s\n", PQerrorMessage(conn));
        PQfinish(conn);
        return -1;
    }

    /* Prepare the upsert statement */
    PGresult *res = PQprepare(conn, "upsert_event", UPSERT_SQL, 5, NULL);
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "[SYNC] PQprepare: %s\n", PQerrorMessage(conn));
        PQclear(res);
        PQfinish(conn);
        return -1;
    }
    PQclear(res);

    /* Begin transaction */
    res = PQexec(conn, "BEGIN");
    PQclear(res);

    int64_t *flushed_ids = calloc((size_t)count, sizeof(int64_t));
    int      flushed     = 0;

    for (int i = 0; i < count; i++) {
        buffer_event_t *ev = &events[i];

        char device_id[64];
        extract_device_id(ev->topic, device_id, sizeof(device_id));

        char ts_str[32];
        snprintf(ts_str, sizeof(ts_str), "%lld", (long long)ev->ts);

        const char *params[5] = {
            device_id,
            ev->topic,
            (const char *)ev->payload,   /* JSONB as text */
            ts_str,
            ctx->edge_node_id
        };
        int param_lengths[5] = {
            0, 0,
            (int)ev->payload_len,        /* binary blob length */
            0, 0
        };
        int param_formats[5] = {0, 0, 0, 0, 0}; /* all text */

        res = PQexecPrepared(conn, "upsert_event",
                              5, params,
                              param_lengths, param_formats,
                              0 /* result as text */);

        if (PQresultStatus(res) == PGRES_COMMAND_OK) {
            flushed_ids[flushed++] = ev->id;
        } else {
            fprintf(stderr, "[SYNC] upsert failed for id=%lld: %s\n",
                    (long long)ev->id, PQerrorMessage(conn));
        }
        PQclear(res);
    }

    /* Commit */
    res = PQexec(conn, "COMMIT");
    PQclear(res);
    PQfinish(conn);

    /* Mark as flushed in SQLite */
    if (flushed > 0) {
        buffer_events_mark_flushed(read_buf, flushed_ids, flushed);
        fprintf(stderr, "[SYNC] flushed %d/%d events to Postgres\n", flushed, count);
    }

    free(flushed_ids);
    return flushed;
}

/* ── Sync loop ───────────────────────────────────────────────────────────── */

static void do_sync(sync_ctx_t *ctx) {
    /* Open a SEPARATE SQLite connection for reads (WAL allows concurrent access) */
    buffer_t read_buf = {0};
    if (buffer_init(&read_buf, SYNC_DB_PATH) != 0) {
        fprintf(stderr, "[SYNC] failed to open read buffer\n");
        return;
    }

    buffer_event_t *events = calloc(BUFFER_FLUSH_LIMIT, sizeof(buffer_event_t));
    if (!events) {
        buffer_close(&read_buf);
        return;
    }

    int count = buffer_events_read_unflushed(&read_buf, events, BUFFER_FLUSH_LIMIT);
    if (count > 0) {
        pg_flush(ctx, &read_buf, events, count);
    } else if (count == 0) {
        fprintf(stderr, "[SYNC] no unflushed events\n");
    } else {
        fprintf(stderr, "[SYNC] error reading buffer\n");
    }

    buffer_events_free(events, count);
    free(events);
    buffer_close(&read_buf);
}

static void *sync_thread_fn(void *arg) {
    sync_ctx_t *ctx = arg;
    uint32_t interval = ctx->interval_sec > 0
                        ? ctx->interval_sec
                        : SYNC_INTERVAL_SEC;

    fprintf(stderr, "[SYNC] thread started, interval=%us, node=%s\n",
            interval, ctx->edge_node_id);

    while (!atomic_load(&ctx->stop)) {
        /* Sleep in 1-second increments so we can respond to stop quickly */
        for (uint32_t i = 0; i < interval; i++) {
            if (atomic_load(&ctx->stop)) goto done;
            sleep(1);
        }
        do_sync(ctx);
    }

done:
    /* Final flush on shutdown */
    fprintf(stderr, "[SYNC] thread stopping — final flush\n");
    do_sync(ctx);
    return NULL;
}

/* ── Public API ──────────────────────────────────────────────────────────── */

int sync_start(sync_ctx_t *ctx) {
    if (!ctx || ctx->pg_connstr[0] == '\0') return -1;
    g_ctx = ctx;
    atomic_store(&ctx->stop, false);
    return pthread_create(&g_thread, NULL, sync_thread_fn, ctx);
}

void sync_stop(sync_ctx_t *ctx) {
    if (!ctx) return;
    atomic_store(&ctx->stop, true);
    pthread_join(g_thread, NULL);
}

void sync_flush_now(sync_ctx_t *ctx) {
    if (!ctx) return;
    do_sync(ctx);
}
