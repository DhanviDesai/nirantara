#ifndef NIRANTARA_NET_H
#define NIRANTARA_NET_H

/**
 * nirantara-net — Edge-native networking library
 *
 * Provides: ECDSA key generation, CSR/enrollment, mTLS context, MQTT client.
 * Designed to compile unchanged on ARM Linux (vehicle telematics target).
 *
 * Thread safety: nr_ctx_t is NOT thread-safe. Do not share a context across
 * threads. The internal mosquitto loop thread is managed by the library.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Error codes ─────────────────────────────────────────────────────────── */

typedef enum {
    NR_OK           =  0,
    NR_ERR_PARAM    = -1,   /* NULL or invalid argument                     */
    NR_ERR_MEM      = -2,   /* malloc / alloc failure                       */
    NR_ERR_TLS      = -3,   /* OpenSSL error (check NR_LOG output)          */
    NR_ERR_MQTT     = -4,   /* libmosquitto error                           */
    NR_ERR_ENROLL   = -5,   /* Enrollment HTTP request failed               */
    NR_ERR_KEYSTORE = -6,   /* Key generation or serialisation failed       */
    NR_ERR_IO       = -7,   /* File or network I/O error                    */
    NR_ERR_PROTO    = -8,   /* Unexpected server response                   */
} nr_error_t;

/* ── Configuration ───────────────────────────────────────────────────────── */

#define NR_MAX_IP_LEN     64
#define NR_MAX_PEM_LEN    8192

typedef struct {
    char     server_ip[NR_MAX_IP_LEN];  /* Edge node IP (no domain needed)  */
    uint16_t mqtt_port;                 /* Default: 8883                    */
    uint16_t enroll_port;               /* Default: 443                     */
    uint32_t keepalive_sec;             /* MQTT keepalive. Default: 30      */
    char     ca_cert_pem[NR_MAX_PEM_LEN]; /* Pinned CA cert, PEM encoded   */
} nr_config_t;

/* ── Opaque context ──────────────────────────────────────────────────────── */

typedef struct nr_ctx nr_ctx_t;

/* ── Message callback ────────────────────────────────────────────────────── */

/**
 * Called on each incoming MQTT message (from the mosquitto loop thread).
 * Do NOT call nr_publish() from within this callback — deadlock risk.
 * Copy data if you need it after the callback returns.
 */
typedef void (*nr_message_cb_t)(
    const char    *topic,
    const uint8_t *payload,
    size_t         len,
    void          *userdata
);

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

/**
 * Allocate a new context. Returns NULL on OOM.
 * Always pair with nr_destroy().
 */
nr_ctx_t   *nr_create(void);

/**
 * Initialise context with config. Parses and pins the CA cert.
 * Must be called before any other function.
 */
nr_error_t  nr_init(nr_ctx_t *ctx, const nr_config_t *cfg);

/**
 * Free all resources. Disconnects MQTT if connected.
 * ctx pointer is invalid after this call.
 */
void        nr_destroy(nr_ctx_t *ctx);

/* ── Key and certificate management ─────────────────────────────────────── */

/**
 * Generate an ECDSA P-256 key pair and store it in the context.
 * On a real device, the private key should be moved to the platform keystore
 * (iOS Keychain / Android Keystore) after generation.
 */
nr_error_t  nr_generate_keypair(nr_ctx_t *ctx);

/**
 * Get the public key as a PEM-encoded CSR, suitable for sending to
 * the enrollment endpoint. Buffer must be at least NR_MAX_PEM_LEN bytes.
 */
nr_error_t  nr_get_csr_pem(nr_ctx_t   *ctx,
                             const char *device_id,
                             char       *csr_out,
                             size_t      csr_out_len);

/**
 * Enroll this device: sends the CSR to the enrollment endpoint and
 * stores the returned signed certificate in cert_out.
 * cert_out must be at least NR_MAX_PEM_LEN bytes.
 *
 * This is a blocking call (HTTP round-trip). Call once on first run;
 * store the returned cert in the platform keystore.
 */
nr_error_t  nr_enroll(nr_ctx_t   *ctx,
                       const char *device_id,
                       char       *cert_out,
                       size_t      cert_out_len);

/* ── MQTT ────────────────────────────────────────────────────────────────── */

/**
 * Establish an mTLS MQTT connection to the edge node.
 * client_cert_pem and client_key_pem are PEM strings obtained from
 * nr_enroll() and nr_get_private_key_pem() respectively.
 */
nr_error_t  nr_connect(nr_ctx_t   *ctx,
                        const char *client_cert_pem,
                        const char *client_key_pem);

/**
 * Publish a message. Must be called after nr_connect().
 * qos: 0 = at most once, 1 = at least once (recommended), 2 = exactly once.
 * This call is non-blocking (mosquitto queues the message).
 */
nr_error_t  nr_publish(nr_ctx_t      *ctx,
                        const char    *topic,
                        const uint8_t *payload,
                        size_t         len,
                        int            qos);

/**
 * Subscribe to a topic pattern. Wildcard '+' and '#' supported.
 * cb is invoked from the internal loop thread — do not block in the callback.
 */
nr_error_t  nr_subscribe(nr_ctx_t       *ctx,
                           const char    *topic,
                           nr_message_cb_t cb,
                           void          *userdata);

/**
 * Disconnect and stop the MQTT loop. Blocks until the loop thread exits.
 */
void        nr_disconnect(nr_ctx_t *ctx);

/* ── Key export (for platform keystore migration) ────────────────────────── */

/**
 * Serialise the in-memory private key to PEM. Use only for migration to
 * platform keystore — zero and free the buffer immediately after.
 * buf must be NR_MAX_PEM_LEN bytes.
 */
nr_error_t  nr_get_private_key_pem(nr_ctx_t *ctx,
                                    char     *buf,
                                    size_t    buf_len);

/* ── Diagnostics ─────────────────────────────────────────────────────────── */

/** Human-readable error string for an nr_error_t code. */
const char *nr_strerror(nr_error_t err);

/** Library version string, e.g. "0.1.0". */
const char *nr_version(void);

#ifdef __cplusplus
}
#endif

#endif /* NIRANTARA_NET_H */
