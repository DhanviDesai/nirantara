#define _POSIX_C_SOURCE 200809L
#include "nirantara/internal.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define NR_VERSION "0.1.0"

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

nr_ctx_t *nr_create(void) {
    nr_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    if (pthread_mutex_init(&ctx->subs_lock, NULL) != 0) {
        free(ctx);
        return NULL;
    }

    atomic_store(&ctx->mqtt_connected, false);
    ctx->initialised = false;
    return ctx;
}

nr_error_t nr_init(nr_ctx_t *ctx, const nr_config_t *cfg) {
    if (!ctx || !cfg) return NR_ERR_PARAM;
    if (ctx->initialised) return NR_ERR_PARAM;

    /* Validate required fields */
    if (cfg->server_ip[0] == '\0') return NR_ERR_PARAM;
    if (cfg->ca_cert_pem[0] == '\0') return NR_ERR_PARAM;

    memcpy(&ctx->cfg, cfg, sizeof(nr_config_t));

    /* Apply defaults */
    if (ctx->cfg.mqtt_port == 0)      ctx->cfg.mqtt_port    = 8883;
    if (ctx->cfg.enroll_port == 0)    ctx->cfg.enroll_port  = 443;
    if (ctx->cfg.keepalive_sec == 0)  ctx->cfg.keepalive_sec = 30;

    /* Initialise OpenSSL and build pinned SSL_CTX */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    nr_error_t rc = nr__tls_init_ctx(ctx);
    if (rc != NR_OK) return rc;

    /* Initialise mosquitto library (idempotent) */
    mosquitto_lib_init();

    ctx->initialised = true;
    NR_LOG_INFO("nr_init: server=%s mqtt_port=%u enroll_port=%u",
                ctx->cfg.server_ip, ctx->cfg.mqtt_port, ctx->cfg.enroll_port);
    return NR_OK;
}

void nr_destroy(nr_ctx_t *ctx) {
    if (!ctx) return;

    nr_disconnect(ctx);
    nr__mqtt_free(ctx);
    nr__tls_free_ctx(ctx);
    nr__keystore_free(ctx);

    if (ctx->csr) {
        X509_REQ_free(ctx->csr);
        ctx->csr = NULL;
    }

    pthread_mutex_destroy(&ctx->subs_lock);
    mosquitto_lib_cleanup();

    memset(ctx->client_cert_pem, 0, sizeof(ctx->client_cert_pem));
    free(ctx);
}

/* ── Key management (delegates to keystore.c) ────────────────────────────── */

nr_error_t nr_generate_keypair(nr_ctx_t *ctx) {
    if (!ctx || !ctx->initialised) return NR_ERR_PARAM;
    return nr__keystore_generate_ec(ctx);
}

nr_error_t nr_get_private_key_pem(nr_ctx_t *ctx, char *buf, size_t buf_len) {
    if (!ctx || !buf || buf_len < NR_MAX_PEM_LEN) return NR_ERR_PARAM;
    if (!ctx->keypair) return NR_ERR_KEYSTORE;
    return nr__keystore_pem_privkey(ctx, buf, buf_len);
}

/* ── CSR and enrollment (delegates to enroll.c) ──────────────────────────── */

nr_error_t nr_get_csr_pem(nr_ctx_t   *ctx,
                            const char *device_id,
                            char       *csr_out,
                            size_t      csr_out_len) {
    if (!ctx || !device_id || !csr_out) return NR_ERR_PARAM;
    if (!ctx->keypair) return NR_ERR_KEYSTORE;
    return nr__enroll_build_csr(ctx, device_id, csr_out, csr_out_len);
}

nr_error_t nr_enroll(nr_ctx_t   *ctx,
                      const char *device_id,
                      char       *cert_out,
                      size_t      cert_out_len) {
    if (!ctx || !device_id || !cert_out) return NR_ERR_PARAM;
    if (!ctx->keypair) return NR_ERR_KEYSTORE;

    /* Build CSR */
    char csr_pem[NR_MAX_PEM_LEN] = {0};
    nr_error_t rc = nr__enroll_build_csr(ctx, device_id, csr_pem, sizeof(csr_pem));
    if (rc != NR_OK) return rc;

    /* Send to enrollment endpoint */
    rc = nr__enroll_request(ctx, csr_pem, device_id, cert_out, cert_out_len);
    if (rc != NR_OK) return rc;

    /* Cache locally in context */
    size_t cert_len = strnlen(cert_out, cert_out_len);
    if (cert_len >= sizeof(ctx->client_cert_pem)) return NR_ERR_MEM;
    memcpy(ctx->client_cert_pem, cert_out, cert_len + 1);

    NR_LOG_INFO("nr_enroll: enrolled device_id=%s", device_id);
    return NR_OK;
}

/* ── MQTT (delegates to mqtt.c) ──────────────────────────────────────────── */

nr_error_t nr_connect(nr_ctx_t   *ctx,
                       const char *client_cert_pem,
                       const char *client_key_pem) {
    if (!ctx || !client_cert_pem || !client_key_pem) return NR_ERR_PARAM;
    if (!ctx->initialised) return NR_ERR_PARAM;

    nr_error_t rc = nr__mqtt_init(ctx);
    if (rc != NR_OK) return rc;

    return nr__mqtt_connect(ctx, client_cert_pem, client_key_pem);
}

nr_error_t nr_publish(nr_ctx_t      *ctx,
                       const char    *topic,
                       const uint8_t *payload,
                       size_t         len,
                       int            qos) {
    if (!ctx || !topic || !payload) return NR_ERR_PARAM;
    if (!atomic_load(&ctx->mqtt_connected)) return NR_ERR_MQTT;

    int ret = mosquitto_publish(ctx->mosq,
                                NULL,               /* mid: don't track */
                                topic,
                                (int)len,
                                payload,
                                qos,
                                false);             /* retain=false */
    if (ret != MOSQ_ERR_SUCCESS) {
        NR_LOG_ERR("nr_publish: %s", mosquitto_strerror(ret));
        return NR_ERR_MQTT;
    }
    return NR_OK;
}

nr_error_t nr_subscribe(nr_ctx_t       *ctx,
                          const char    *topic,
                          nr_message_cb_t cb,
                          void          *userdata) {
    if (!ctx || !topic || !cb) return NR_ERR_PARAM;
    if (!atomic_load(&ctx->mqtt_connected)) return NR_ERR_MQTT;

    /* Store callback */
    pthread_mutex_lock(&ctx->subs_lock);
    int slot = -1;
    for (int i = 0; i < NR_MAX_SUBSCRIPTIONS; i++) {
        if (!ctx->subs[i].active) { slot = i; break; }
    }
    if (slot < 0) {
        pthread_mutex_unlock(&ctx->subs_lock);
        NR_LOG_ERR("nr_subscribe: max subscriptions (%d) reached", NR_MAX_SUBSCRIPTIONS);
        return NR_ERR_PARAM;
    }
    snprintf(ctx->subs[slot].topic, sizeof(ctx->subs[slot].topic), "%s", topic);
    ctx->subs[slot].cb       = cb;
    ctx->subs[slot].userdata = userdata;
    ctx->subs[slot].active   = true;
    pthread_mutex_unlock(&ctx->subs_lock);

    int ret = mosquitto_subscribe(ctx->mosq, NULL, topic, 1 /* QoS 1 */);
    if (ret != MOSQ_ERR_SUCCESS) {
        NR_LOG_ERR("nr_subscribe: %s", mosquitto_strerror(ret));
        ctx->subs[slot].active = false;
        return NR_ERR_MQTT;
    }

    NR_LOG_INFO("nr_subscribe: topic=%s", topic);
    return NR_OK;
}

void nr_disconnect(nr_ctx_t *ctx) {
    if (!ctx) return;
    nr__mqtt_disconnect(ctx);
}

/* ── Diagnostics ─────────────────────────────────────────────────────────── */

const char *nr_strerror(nr_error_t err) {
    switch (err) {
        case NR_OK:           return "Success";
        case NR_ERR_PARAM:    return "Invalid parameter";
        case NR_ERR_MEM:      return "Memory allocation failed";
        case NR_ERR_TLS:      return "TLS / OpenSSL error";
        case NR_ERR_MQTT:     return "MQTT error";
        case NR_ERR_ENROLL:   return "Enrollment failed";
        case NR_ERR_KEYSTORE: return "Key generation / serialisation error";
        case NR_ERR_IO:       return "I/O error";
        case NR_ERR_PROTO:    return "Unexpected server response";
        default:              return "Unknown error";
    }
}

const char *nr_version(void) {
    return NR_VERSION;
}
