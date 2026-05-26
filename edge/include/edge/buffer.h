#ifndef EDGE_BUFFER_H
#define EDGE_BUFFER_H

#include <stddef.h>
#include <stdint.h>
#include <sqlite3.h>

/**
 * SQLite-backed event buffer for the edge sync agent.
 *
 * Operates in WAL mode — the sync thread can read (SELECT unflushed)
 * concurrently with the MQTT subscriber writing (INSERT events)
 * using a separate sqlite3 connection handle.
 */

#define BUFFER_DB_PATH      "/var/lib/nirantara/edge.db"
#define BUFFER_MAX_TOPIC    256
#define BUFFER_FLUSH_LIMIT  1000    /* max rows per sync batch */

typedef struct {
    sqlite3 *db;
} buffer_t;

typedef struct {
    int64_t     id;
    char        topic[BUFFER_MAX_TOPIC];
    uint8_t    *payload;
    size_t      payload_len;
    int64_t     ts;
} buffer_event_t;

/** Initialise the buffer, creating the DB and schema if needed. */
int buffer_init(buffer_t *buf, const char *db_path);

/** Insert one event. Called from the MQTT message callback (main thread). */
int buffer_event_insert(buffer_t      *buf,
                        const char    *topic,
                        const uint8_t *payload,
                        size_t         payload_len);

/**
 * Read up to BUFFER_FLUSH_LIMIT unflushed events into caller-allocated array.
 * Caller must call buffer_events_free() on the returned array.
 * Returns number of events read, or -1 on error.
 */
int buffer_events_read_unflushed(buffer_t       *buf,
                                  buffer_event_t *events,
                                  int             max_events);

/**
 * Mark a list of event IDs as flushed.
 * ids: array of int64_t event IDs. count: length of array.
 */
int buffer_events_mark_flushed(buffer_t      *buf,
                                const int64_t *ids,
                                int            count);

/** Free payload buffers in an events array. */
void buffer_events_free(buffer_event_t *events, int count);

/** Close the DB handle. */
void buffer_close(buffer_t *buf);

#endif /* EDGE_BUFFER_H */
