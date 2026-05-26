#ifndef NIRANTARA_INTERNAL_H
#define NIRANTARA_INTERNAL_H

/**
 * Internal header — NOT part of the public API.
 * Do not include from outside lib/nirantara-net/src/.
 */

#include "nirantara/net.h"

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <mosquitto.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>

/* ── Logging ─────────────────────────────────────────────────────────────── */

#define NR_LOG_INFO(fmt, ...) \
    fprintf(stderr, "[NR INFO]  " fmt "\n", ##__VA_ARGS__)

#define NR_LOG_ERR(fmt, ...) \
    fprintf(stderr, "[NR ERROR] %s:%d " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#define NR_LOG_SSL_ERR(ctx_str) \
    do { \
        unsigned long _e; \
        while ((_e = ERR_get_error()) != 0) \
            NR_LOG_ERR("%s: %s", (ctx_str), ERR_reason_error_string(_e)); \
    } while (0)

/* ── Subscribe slot ──────────────────────────────────────────────────────── */

#define NR_MAX_SUBSCRIPTIONS 16

typedef struct {
    char            topic[256];
    nr_message_cb_t cb;
    void           *userdata;
    bool            active;
} nr_sub_slot_t;

/* ── Context (full definition, private) ──────────────────────────────────── */

struct nr_ctx {
    /* Config */
    nr_config_t     cfg;

    /* TLS */
    SSL_CTX        *ssl_ctx;        /* Client SSL context with pinned CA     */

    /* Keys and cert */
    EVP_PKEY       *keypair;        /* In-memory ECDSA key pair              */
    X509_REQ       *csr;            /* Last generated CSR                    */
    char            client_cert_pem[NR_MAX_PEM_LEN]; /* Enrolled cert       */

    /* MQTT */
    struct mosquitto *mosq;         /* Mosquitto client handle               */
    _Atomic bool     mqtt_connected;

    /* Subscriptions */
    nr_sub_slot_t    subs[NR_MAX_SUBSCRIPTIONS];
    pthread_mutex_t  subs_lock;

    /* State */
    bool             initialised;
};

/* ── Internal function prototypes ────────────────────────────────────────── */

/* tls.c */
nr_error_t nr__tls_init_ctx(nr_ctx_t *ctx);
void       nr__tls_free_ctx(nr_ctx_t *ctx);

/* keystore.c */
nr_error_t nr__keystore_generate_ec(nr_ctx_t *ctx);
nr_error_t nr__keystore_pem_privkey(nr_ctx_t *ctx, char *buf, size_t len);
void nr__keystore_free(nr_ctx_t *ctx);

/* enroll.c */
nr_error_t nr__enroll_build_csr(nr_ctx_t   *ctx,
                                  const char *device_id,
                                  char       *pem_out,
                                  size_t      pem_out_len);
nr_error_t nr__enroll_request(nr_ctx_t   *ctx,
                               const char *csr_pem,
                               const char *device_id,
                               char       *cert_out,
                               size_t      cert_out_len);

/* mqtt.c */
nr_error_t nr__mqtt_init(nr_ctx_t *ctx);
nr_error_t nr__mqtt_connect(nr_ctx_t   *ctx,
                              const char *client_cert_pem,
                              const char *client_key_pem);
void       nr__mqtt_disconnect(nr_ctx_t *ctx);
void       nr__mqtt_free(nr_ctx_t *ctx);

#endif /* NIRANTARA_INTERNAL_H */
