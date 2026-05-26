#include "nirantara/internal.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <string.h>

/**
 * Build an SSL_CTX that:
 *  - Uses TLS 1.2 minimum
 *  - Trusts ONLY the pinned CA cert from cfg.ca_cert_pem
 *  - Verifies peer certificates
 */
nr_error_t nr__tls_init_ctx(nr_ctx_t *ctx) {
    SSL_CTX *ssl_ctx = NULL;
    X509    *ca      = NULL;
    BIO     *bio     = NULL;
    nr_error_t rc    = NR_ERR_TLS;

    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        NR_LOG_SSL_ERR("SSL_CTX_new");
        goto out;
    }

    /* Minimum TLS 1.2 — non-negotiable */
    if (!SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION)) {
        NR_LOG_SSL_ERR("SSL_CTX_set_min_proto_version");
        goto out;
    }

    /* Load the pinned CA cert from PEM string */
    bio = BIO_new_mem_buf(ctx->cfg.ca_cert_pem, -1);
    if (!bio) {
        NR_LOG_SSL_ERR("BIO_new_mem_buf");
        goto out;
    }

    ca = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!ca) {
        NR_LOG_SSL_ERR("PEM_read_bio_X509 (CA cert)");
        goto out;
    }

    /* Build a fresh trust store with ONLY our CA — no system CAs */
    X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx);
    if (X509_STORE_add_cert(store, ca) != 1) {
        NR_LOG_SSL_ERR("X509_STORE_add_cert");
        goto out;
    }

    /* Require peer cert verification — NEVER disable this */
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    ctx->ssl_ctx = ssl_ctx;
    ssl_ctx = NULL;  /* ownership transferred */
    rc = NR_OK;

    NR_LOG_INFO("%s", "tls: SSL_CTX initialised, TLS 1.2+ with pinned CA");

out:
    if (bio)     BIO_free(bio);
    if (ca)      X509_free(ca);
    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    return rc;
}

void nr__tls_free_ctx(nr_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->ssl_ctx) {
        SSL_CTX_free(ctx->ssl_ctx);
        ctx->ssl_ctx = NULL;
    }
}
