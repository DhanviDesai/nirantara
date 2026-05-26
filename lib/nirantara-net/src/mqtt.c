#define _POSIX_C_SOURCE 200809L
#include <unistd.h>
#include "nirantara/internal.h"

#include <mosquitto.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * mosquitto TLS notes:
 * mosquitto_tls_set() takes file paths, not in-memory PEM.
 * We write the client cert and key to temp files, connect, then unlink.
 * This is the standard pattern for libmosquitto mTLS.
 *
 * TODO: On embedded target, use a ramdisk path (e.g. /dev/shm).
 */

#define TMP_CERT_PATH "/tmp/nr_client_cert.pem"
#define TMP_KEY_PATH  "/tmp/nr_client_key.pem"

/* ── Mosquitto callbacks ─────────────────────────────────────────────────── */

static void on_connect(struct mosquitto *mosq, void *userdata, int rc) {
    nr_ctx_t *ctx = userdata;
    (void)mosq;
    if (rc == 0) {
        atomic_store(&ctx->mqtt_connected, true);
        NR_LOG_INFO("mqtt: connected to %s:%u", ctx->cfg.server_ip, ctx->cfg.mqtt_port);
    } else {
        atomic_store(&ctx->mqtt_connected, false);
        NR_LOG_ERR("mqtt: connect failed, rc=%d (%s)",
                   rc, mosquitto_connack_string(rc));
    }
}

static void on_disconnect(struct mosquitto *mosq, void *userdata, int rc) {
    nr_ctx_t *ctx = userdata;
    (void)mosq;
    atomic_store(&ctx->mqtt_connected, false);
    if (rc != 0) {
        NR_LOG_ERR("mqtt: unexpected disconnect, rc=%d", rc);
    } else {
        NR_LOG_INFO("%s", "mqtt: disconnected cleanly");
    }
}

static void on_message(struct mosquitto         *mosq,
                        void                    *userdata,
                        const struct mosquitto_message *msg) {
    nr_ctx_t *ctx = userdata;
    (void)mosq;

    pthread_mutex_lock(&ctx->subs_lock);
    for (int i = 0; i < NR_MAX_SUBSCRIPTIONS; i++) {
        if (!ctx->subs[i].active) continue;

        bool match = false;
        mosquitto_topic_matches_sub(ctx->subs[i].topic, msg->topic, &match);
        if (match) {
            /* Unlock before invoking callback to avoid deadlock */
            nr_message_cb_t cb       = ctx->subs[i].cb;
            void           *cb_userdata = ctx->subs[i].userdata;
            pthread_mutex_unlock(&ctx->subs_lock);
            cb(msg->topic,
               (const uint8_t *)msg->payload,
               (size_t)msg->payloadlen,
               cb_userdata);
            pthread_mutex_lock(&ctx->subs_lock);
        }
    }
    pthread_mutex_unlock(&ctx->subs_lock);
}

static void on_log(struct mosquitto *mosq, void *userdata, int level, const char *str) {
    (void)mosq; (void)userdata;
    if (level == MOSQ_LOG_ERR || level == MOSQ_LOG_WARNING) {
        NR_LOG_ERR("mosquitto: %s", str);
    }
}

/* ── Init / connect / disconnect ─────────────────────────────────────────── */

nr_error_t nr__mqtt_init(nr_ctx_t *ctx) {
    if (ctx->mosq) return NR_OK;  /* already initialised */

    ctx->mosq = mosquitto_new(NULL, true, ctx);
    if (!ctx->mosq) {
        NR_LOG_ERR("%s", "mqtt: mosquitto_new failed (OOM or bad params)");
        return NR_ERR_MQTT;
    }

    mosquitto_connect_callback_set(ctx->mosq, on_connect);
    mosquitto_disconnect_callback_set(ctx->mosq, on_disconnect);
    mosquitto_message_callback_set(ctx->mosq, on_message);
    mosquitto_log_callback_set(ctx->mosq, on_log);

    /* MQTT 3.1.1 keepalive */
    return NR_OK;
}

nr_error_t nr__mqtt_connect(nr_ctx_t   *ctx,
                              const char *client_cert_pem,
                              const char *client_key_pem) {
    nr_error_t rc = NR_ERR_MQTT;

    /* Write cert and key to temp files for libmosquitto */
    FILE *f;

    f = fopen(TMP_CERT_PATH, "w");
    if (!f) { NR_LOG_ERR("mqtt: cannot write %s", TMP_CERT_PATH); return NR_ERR_IO; }
    fputs(client_cert_pem, f);
    fclose(f);

    f = fopen(TMP_KEY_PATH, "w");
    if (!f) {
        unlink(TMP_CERT_PATH);
        NR_LOG_ERR("mqtt: cannot write %s", TMP_KEY_PATH);
        return NR_ERR_IO;
    }
    fputs(client_key_pem, f);
    fclose(f);

    /*
     * mosquitto_tls_set:
     *   cafile     = NULL  → we set SSL_CTX directly via mosquitto_tls_opts_set
     *   certfile   = client cert path
     *   keyfile    = client key path
     *   pw_callback = NULL (no passphrase)
     *
     * NOTE: We pass cafile here as well so mosquitto builds its own verify chain.
     * The pinned CA is written to a separate temp file.
     */
    const char *cafile = NULL;   /* mosquitto will use system CAs if NULL */
    /* For strict CA pinning with mosquitto we write the CA to disk too */
    #define TMP_CA_PATH "/tmp/nr_ca.pem"
    FILE *caf = fopen(TMP_CA_PATH, "w");
    if (caf) {
        fputs(ctx->cfg.ca_cert_pem, caf);
        fclose(caf);
        cafile = TMP_CA_PATH;
    }

    int ret = mosquitto_tls_set(ctx->mosq,
                                 cafile,
                                 NULL,            /* capath */
                                 TMP_CERT_PATH,
                                 TMP_KEY_PATH,
                                 NULL);           /* no pw callback */
    if (ret != MOSQ_ERR_SUCCESS) {
        NR_LOG_ERR("mqtt: mosquitto_tls_set: %s", mosquitto_strerror(ret));
        goto cleanup;
    }

    /* Enforce TLS 1.2 minimum */
    ret = mosquitto_tls_opts_set(ctx->mosq,
                                  SSL_VERIFY_PEER,
                                  "tlsv1.2",
                                  NULL);          /* no cipher list override */
    if (ret != MOSQ_ERR_SUCCESS) {
        NR_LOG_ERR("mqtt: mosquitto_tls_opts_set: %s", mosquitto_strerror(ret));
        goto cleanup;
    }

    ret = mosquitto_connect(ctx->mosq,
                             ctx->cfg.server_ip,
                             ctx->cfg.mqtt_port,
                             (int)ctx->cfg.keepalive_sec);
    if (ret != MOSQ_ERR_SUCCESS) {
        NR_LOG_ERR("mqtt: mosquitto_connect: %s", mosquitto_strerror(ret));
        goto cleanup;
    }

    /* Start the network loop in a background thread */
    ret = mosquitto_loop_start(ctx->mosq);
    if (ret != MOSQ_ERR_SUCCESS) {
        NR_LOG_ERR("mqtt: mosquitto_loop_start: %s", mosquitto_strerror(ret));
        goto cleanup;
    }

    /* Wait briefly for on_connect callback */
    for (int i = 0; i < 50; i++) {
        if (atomic_load(&ctx->mqtt_connected)) break;
        struct timespec ts = {0, 100000000L}; nanosleep(&ts, NULL);
    }

    if (!atomic_load(&ctx->mqtt_connected)) {
        NR_LOG_ERR("%s", "mqtt: timed out waiting for connection");
        mosquitto_loop_stop(ctx->mosq, true);
        goto cleanup;
    }

    rc = NR_OK;

cleanup:
    /* Remove temp key file immediately — cert can stay for reconnect */
    unlink(TMP_KEY_PATH);
    /* Keep cert and ca files; mosquitto may need them on reconnect */
    return rc;
}

void nr__mqtt_disconnect(nr_ctx_t *ctx) {
    if (!ctx || !ctx->mosq) return;
    if (atomic_load(&ctx->mqtt_connected)) {
        mosquitto_disconnect(ctx->mosq);
    }
    mosquitto_loop_stop(ctx->mosq, false);
    atomic_store(&ctx->mqtt_connected, false);

    /* Clean up temp files */
    unlink(TMP_CERT_PATH);
    unlink(TMP_KEY_PATH);
    unlink(TMP_CA_PATH);
}

void nr__mqtt_free(nr_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->mosq) {
        mosquitto_destroy(ctx->mosq);
        ctx->mosq = NULL;
    }
}
