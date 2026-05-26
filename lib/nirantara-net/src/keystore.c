#include "nirantara/internal.h"

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>

/**
 * Generate an ECDSA P-256 key pair and store in ctx->keypair.
 *
 * In production on a real device:
 *   - The key should be generated inside the secure enclave
 *     (iOS SecKeyCreateRandomKey / Android Keystore generateKeyPair)
 *   - The private component never leaves the enclave
 *   - The FFI layer handles this; the C library holds only an in-memory
 *     reference for the desktop/embedded Linux target
 */
nr_error_t nr__keystore_generate_ec(nr_ctx_t *ctx) {
    EVP_PKEY_CTX *kctx = NULL;
    EVP_PKEY     *key  = NULL;
    nr_error_t    rc   = NR_ERR_KEYSTORE;

    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!kctx) {
        NR_LOG_SSL_ERR("EVP_PKEY_CTX_new_id");
        goto out;
    }

    if (EVP_PKEY_keygen_init(kctx) <= 0) {
        NR_LOG_SSL_ERR("EVP_PKEY_keygen_init");
        goto out;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_X9_62_prime256v1) <= 0) {
        NR_LOG_SSL_ERR("EVP_PKEY_CTX_set_ec_paramgen_curve_nid (P-256)");
        goto out;
    }

    if (EVP_PKEY_keygen(kctx, &key) <= 0) {
        NR_LOG_SSL_ERR("EVP_PKEY_keygen");
        goto out;
    }

    /* Free any existing key */
    if (ctx->keypair) {
        EVP_PKEY_free(ctx->keypair);
    }
    ctx->keypair = key;
    key = NULL;

    rc = NR_OK;
    NR_LOG_INFO("%s", "keystore: generated ECDSA P-256 key pair");

out:
    if (kctx) EVP_PKEY_CTX_free(kctx);
    if (key)  EVP_PKEY_free(key);
    return rc;
}

/**
 * Serialise the private key to PEM.
 * Caller MUST zero the buffer immediately after use:
 *   OPENSSL_cleanse(buf, buf_len);
 */
nr_error_t nr__keystore_pem_privkey(nr_ctx_t *ctx, char *buf, size_t buf_len) {
    if (!ctx->keypair) return NR_ERR_KEYSTORE;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) return NR_ERR_MEM;

    nr_error_t rc = NR_ERR_KEYSTORE;

    if (!PEM_write_bio_PrivateKey(bio, ctx->keypair,
                                   NULL,   /* no encryption */
                                   NULL, 0, NULL, NULL)) {
        NR_LOG_SSL_ERR("PEM_write_bio_PrivateKey");
        goto out;
    }

    BUF_MEM *bptr = NULL;
    BIO_get_mem_ptr(bio, &bptr);

    if (bptr->length >= buf_len) {
        NR_LOG_ERR("keystore: private key PEM too large (%zu >= %zu)",
                   bptr->length, buf_len);
        rc = NR_ERR_MEM;
        goto out;
    }

    memcpy(buf, bptr->data, bptr->length);
    buf[bptr->length] = '\0';
    rc = NR_OK;

out:
    BIO_free(bio);
    return rc;
}

void nr__keystore_free(nr_ctx_t *ctx) {
    if (!ctx) return;
    if (ctx->keypair) {
        EVP_PKEY_free(ctx->keypair);
        ctx->keypair = NULL;
    }
}
