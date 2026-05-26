#include "edge/buffer.h"
#include "edge/sync.h"

#include <mosquitto.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdatomic.h>
#include <errno.h>
#include <sys/stat.h>

/* ── Config from environment ─────────────────────────────────────────────── */

#define ENV_PG_CONNSTR      "NR_PG_CONNSTR"
#define ENV_MQTT_HOST       "NR_MQTT_HOST"
#define ENV_MQTT_PORT       "NR_MQTT_PORT"
#define ENV_MQTT_CA         "NR_MQTT_CA"
#define ENV_MQTT_CERT       "NR_MQTT_CERT"
#define ENV_MQTT_KEY        "NR_MQTT_KEY"
#define ENV_EDGE_NODE_ID    "NR_EDGE_NODE_ID"
#define ENV_SYNC_INTERVAL   "NR_SYNC_INTERVAL"
#define ENV_DB_PATH         "NR_DB_PATH"
#define ENV_SUBSCRIBE_TOPIC "NR_SUBSCRIBE_TOPIC"

/* ── Globals (for signal handler) ────────────────────────────────────────── */

static _Atomic bool       g_running = true;
static sync_ctx_t         g_sync    = {0};
static struct mosquitto  *g_mosq    = NULL;
static buffer_t           g_buf     = {0};

/* ── Signal handler ──────────────────────────────────────────────────────── */

static void on_signal(int sig) {
    fprintf(stderr, "\n[MAIN] signal %d received — shutting down\n", sig);
    atomic_store(&g_running, false);

    /* Final flush */
    if (g_running == false) {
        sync_flush_now(&g_sync);
    }
}

/* ── Mosquitto callbacks ─────────────────────────────────────────────────── */

static void on_connect(struct mosquitto *mosq, void *userdata, int rc) {
    (void)userdata;
    if (rc != 0) {
        fprintf(stderr, "[MAIN] MQTT connect failed: %s\n", mosquitto_connack_string(rc));
        return;
    }
    fprintf(stderr, "[MAIN] MQTT connected\n");

    const char *topic = getenv(ENV_SUBSCRIBE_TOPIC);
    if (!topic) topic = "game/#";

    int ret = mosquitto_subscribe(mosq, NULL, topic, 1);
    if (ret != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "[MAIN] subscribe to '%s' failed: %s\n",
                topic, mosquitto_strerror(ret));
    } else {
        fprintf(stderr, "[MAIN] subscribed to '%s'\n", topic);
    }
}

static void on_disconnect(struct mosquitto *mosq, void *userdata, int rc) {
    (void)mosq; (void)userdata;
    if (rc != 0) {
        fprintf(stderr, "[MAIN] unexpected MQTT disconnect, rc=%d\n", rc);
    }
}

static void on_message(struct mosquitto              *mosq,
                        void                         *userdata,
                        const struct mosquitto_message *msg) {
    (void)mosq; (void)userdata;
    buffer_t *buf = &g_buf;

    int rc = buffer_event_insert(buf,
                                  msg->topic,
                                  (const uint8_t *)msg->payload,
                                  (size_t)msg->payloadlen);
    if (rc != 0) {
        fprintf(stderr, "[MAIN] buffer insert failed for topic=%s\n", msg->topic);
    }
}

static void on_log(struct mosquitto *mosq, void *userdata, int level, const char *str) {
    (void)mosq; (void)userdata;
    if (level == MOSQ_LOG_ERR || level == MOSQ_LOG_WARNING) {
        fprintf(stderr, "[MOSQ] %s\n", str);
    }
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static const char *required_env(const char *name) {
    const char *val = getenv(name);
    if (!val || val[0] == '\0') {
        fprintf(stderr, "[MAIN] required env var %s is not set\n", name);
        exit(EXIT_FAILURE);
    }
    return val;
}

static void ensure_dir(const char *path) {
    /* Create parent directory of a file path */
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", path);
    char *slash = strrchr(tmp, '/');
    if (slash && slash != tmp) {
        *slash = '\0';
        mkdir(tmp, 0700);
    }
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

int main(void) {
    fprintf(stderr, "[MAIN] nirantara edge agent starting\n");

    /* Signal handlers */
    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    /* Read config from environment */
    const char *pg_connstr    = required_env(ENV_PG_CONNSTR);
    const char *mqtt_host     = required_env(ENV_MQTT_HOST);
    const char *mqtt_ca       = required_env(ENV_MQTT_CA);
    const char *mqtt_cert     = required_env(ENV_MQTT_CERT);
    const char *mqtt_key      = required_env(ENV_MQTT_KEY);
    const char *edge_node_id  = getenv(ENV_EDGE_NODE_ID);
    const char *db_path       = getenv(ENV_DB_PATH);

    if (!edge_node_id) edge_node_id = "edge-mumbai-01";
    if (!db_path)      db_path      = BUFFER_DB_PATH;

    uint16_t mqtt_port = 8883;
    const char *port_str = getenv(ENV_MQTT_PORT);
    if (port_str) mqtt_port = (uint16_t)atoi(port_str);

    uint32_t sync_interval = SYNC_INTERVAL_SEC;
    const char *si_str = getenv(ENV_SYNC_INTERVAL);
    if (si_str) sync_interval = (uint32_t)atoi(si_str);

    /* Initialise buffer */
    ensure_dir(db_path);
    if (buffer_init(&g_buf, db_path) != 0) {
        fprintf(stderr, "[MAIN] buffer init failed\n");
        return EXIT_FAILURE;
    }

    /* Start sync thread */
    snprintf(g_sync.pg_connstr,   sizeof(g_sync.pg_connstr),   "%s", pg_connstr);
    snprintf(g_sync.edge_node_id, sizeof(g_sync.edge_node_id), "%s", edge_node_id);
    g_sync.interval_sec = sync_interval;

    if (sync_start(&g_sync) != 0) {
        fprintf(stderr, "[MAIN] sync thread start failed\n");
        buffer_close(&g_buf);
        return EXIT_FAILURE;
    }

    /* Initialise mosquitto */
    mosquitto_lib_init();

    g_mosq = mosquitto_new(edge_node_id, true, NULL);
    if (!g_mosq) {
        fprintf(stderr, "[MAIN] mosquitto_new failed\n");
        sync_stop(&g_sync);
        buffer_close(&g_buf);
        return EXIT_FAILURE;
    }

    mosquitto_connect_callback_set(g_mosq, on_connect);
    mosquitto_disconnect_callback_set(g_mosq, on_disconnect);
    mosquitto_message_callback_set(g_mosq, on_message);
    mosquitto_log_callback_set(g_mosq, on_log);

    /* mTLS */
    int rc = mosquitto_tls_set(g_mosq, mqtt_ca, NULL, mqtt_cert, mqtt_key, NULL);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "[MAIN] mosquitto_tls_set: %s\n", mosquitto_strerror(rc));
        goto cleanup;
    }

    mosquitto_tls_opts_set(g_mosq, SSL_VERIFY_PEER, "tlsv1.2", NULL);

    /* Connect to local Mosquitto broker */
    rc = mosquitto_connect(g_mosq, mqtt_host, mqtt_port, 30);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "[MAIN] mosquitto_connect: %s\n", mosquitto_strerror(rc));
        goto cleanup;
    }

    fprintf(stderr, "[MAIN] connected to broker %s:%u — entering loop\n",
            mqtt_host, mqtt_port);

    /* Main loop — blocks until disconnect or signal */
    while (atomic_load(&g_running)) {
        rc = mosquitto_loop(g_mosq, 1000 /* ms */, 1);
        if (rc != MOSQ_ERR_SUCCESS && rc != MOSQ_ERR_NO_CONN) {
            fprintf(stderr, "[MAIN] mosquitto_loop error: %s\n", mosquitto_strerror(rc));
            /* Attempt reconnect */
            sleep(5);
            mosquitto_reconnect(g_mosq);
        }
    }

cleanup:
    fprintf(stderr, "[MAIN] shutting down\n");
    mosquitto_disconnect(g_mosq);
    mosquitto_destroy(g_mosq);
    mosquitto_lib_cleanup();

    sync_stop(&g_sync);
    buffer_close(&g_buf);

    fprintf(stderr, "[MAIN] clean exit\n");
    return EXIT_SUCCESS;
}
