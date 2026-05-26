#ifndef EDGE_SYNC_H
#define EDGE_SYNC_H

#include "buffer.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>

/**
 * Postgres sync thread.
 *
 * Runs as a pthread. Every SYNC_INTERVAL_SEC seconds:
 *   1. Opens a fresh libpq connection to cloud Postgres
 *   2. Reads up to BUFFER_FLUSH_LIMIT unflushed events from SQLite
 *   3. Batch-upserts to game_events table
 *   4. Marks rows as flushed in SQLite
 *   5. Closes the Postgres connection
 *
 * Uses a SEPARATE sqlite3 connection from the main subscriber (WAL mode).
 */

#define SYNC_INTERVAL_SEC   600     /* 10 minutes */
#define SYNC_DB_PATH        BUFFER_DB_PATH

typedef struct {
    char        pg_connstr[512];    /* libpq connection string              */
    char        edge_node_id[64];   /* identifies this node in Postgres     */
    uint32_t    interval_sec;       /* override SYNC_INTERVAL_SEC if != 0  */
    _Atomic bool stop;              /* set true to request shutdown         */
} sync_ctx_t;

/** Start the sync thread. ctx must remain valid until sync_stop(). */
int  sync_start(sync_ctx_t *ctx);

/** Signal the sync thread to stop and join it. Blocks until done. */
void sync_stop(sync_ctx_t *ctx);

/** Force an immediate flush (called from SIGTERM handler). */
void sync_flush_now(sync_ctx_t *ctx);

#endif /* EDGE_SYNC_H */
