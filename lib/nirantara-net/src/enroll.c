#include "nirantara/internal.h"

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

/* ── CSR construction ────────────────────────────────────────────────────── */

/**
 * Build a PKCS#10 CSR for the given device_id.
 * The CSR is signed with ctx->keypair (ECDSA P-256, SHA-256).
 * Returns PEM-encoded CSR in pem_out.
 */
nr_error_t nr__enroll_build_csr(nr_ctx_t   *ctx,
                                  const char *device_id,
                                  char       *pem_out,
                                  size_t      pem_out_len) {
    X509_REQ *req  = NULL;
    X509_NAME *name = NULL;
    BIO       *bio  = NULL;
    nr_error_t rc   = NR_ERR_ENROLL;

    req = X509_REQ_new();
    if (!req) goto out;

    X509_REQ_set_version(req, 0);  /* version 1 */

    name = X509_REQ_get_subject_name(req);

    /* CN = device_id (stable, unique per device) */
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char *)device_id, -1, -1, 0)) {
        NR_LOG_SSL_ERR("X509_NAME_add_entry CN");
        goto out;
    }

    if (!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
            (const unsigned char *)"Nirantara", -1, -1, 0)) {
        NR_LOG_SSL_ERR("X509_NAME_add_entry O");
        goto out;
    }

    /* Attach public key */
    if (!X509_REQ_set_pubkey(req, ctx->keypair)) {
        NR_LOG_SSL_ERR("X509_REQ_set_pubkey");
        goto out;
    }

    /* Sign with SHA-256 */
    if (X509_REQ_sign(req, ctx->keypair, EVP_sha256()) <= 0) {
        NR_LOG_SSL_ERR("X509_REQ_sign");
        goto out;
    }

    /* Store in context for reuse */
    if (ctx->csr) X509_REQ_free(ctx->csr);
    ctx->csr = X509_REQ_dup(req);

    /* Serialise to PEM */
    bio = BIO_new(BIO_s_mem());
    if (!bio) { rc = NR_ERR_MEM; goto out; }

    if (!PEM_write_bio_X509_REQ(bio, req)) {
        NR_LOG_SSL_ERR("PEM_write_bio_X509_REQ");
        goto out;
    }

    BUF_MEM *bptr = NULL;
    BIO_get_mem_ptr(bio, &bptr);
    if (bptr->length >= pem_out_len) {
        rc = NR_ERR_MEM;
        goto out;
    }

    memcpy(pem_out, bptr->data, bptr->length);
    pem_out[bptr->length] = '\0';
    rc = NR_OK;

    NR_LOG_INFO("enroll: built CSR for device_id=%s", device_id);

out:
    if (bio) BIO_free(bio);
    if (req) X509_REQ_free(req);
    return rc;
}

/* ── HTTP enrollment request ─────────────────────────────────────────────── */

/*
 * Minimal HTTP/1.1 POST over a TLS connection.
 * We avoid libcurl to keep dependencies minimal (ARM embedded target).
 *
 * POST /enroll HTTP/1.1
 * Host: <server_ip>
 * Content-Type: application/x-pem-file
 * X-Device-Id: <device_id>
 * Content-Length: <len>
 *
 * <csr_pem>
 */

#define ENROLL_PATH     "/enroll"
#define ENROLL_BUF_SIZE 16384

static int tcp_connect(const char *ip, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

nr_error_t nr__enroll_request(nr_ctx_t   *ctx,
                               const char *csr_pem,
                               const char *device_id,
                               char       *cert_out,
                               size_t      cert_out_len) {
    SSL       *ssl    = NULL;
    int        fd     = -1;
    char      *buf    = NULL;
    nr_error_t rc     = NR_ERR_ENROLL;

    buf = malloc(ENROLL_BUF_SIZE);
    if (!buf) return NR_ERR_MEM;

    /* TCP connect */
    fd = tcp_connect(ctx->cfg.server_ip, ctx->cfg.enroll_port);
    if (fd < 0) {
        NR_LOG_ERR("enroll: tcp_connect to %s:%u failed: %s",
                   ctx->cfg.server_ip, ctx->cfg.enroll_port, strerror(errno));
        rc = NR_ERR_IO;
        goto out;
    }

    /* TLS handshake (uses the pinned CA SSL_CTX) */
    ssl = SSL_new(ctx->ssl_ctx);
    if (!ssl) { NR_LOG_SSL_ERR("SSL_new"); goto out; }

    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, ctx->cfg.server_ip);

    if (SSL_connect(ssl) != 1) {
        NR_LOG_SSL_ERR("SSL_connect (enroll)");
        goto out;
    }

    /* Build HTTP request */
    size_t csr_len = strlen(csr_pem);
    int req_len = snprintf(buf, ENROLL_BUF_SIZE,
        "POST " ENROLL_PATH " HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/x-pem-file\r\n"
        "X-Device-Id: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        ctx->cfg.server_ip, device_id, csr_len, csr_pem);

    if (req_len <= 0 || req_len >= ENROLL_BUF_SIZE) {
        rc = NR_ERR_MEM;
        goto out;
    }

    /* Send */
    if (SSL_write(ssl, buf, req_len) != req_len) {
        NR_LOG_SSL_ERR("SSL_write (enroll request)");
        rc = NR_ERR_IO;
        goto out;
    }

    /* Read response */
    int total = 0;
    int n;
    memset(buf, 0, ENROLL_BUF_SIZE);
    while ((n = SSL_read(ssl, buf + total, ENROLL_BUF_SIZE - total - 1)) > 0) {
        total += n;
        if (total >= ENROLL_BUF_SIZE - 1) break;
    }
    buf[total] = '\0';

    /* Check HTTP status */
    if (strncmp(buf, "HTTP/1.1 200", 12) != 0 &&
        strncmp(buf, "HTTP/1.0 200", 12) != 0) {
        NR_LOG_ERR("enroll: server returned non-200: %.60s", buf);
        rc = NR_ERR_PROTO;
        goto out;
    }

    /* Find PEM cert in response body (after \r\n\r\n) */
    const char *body = strstr(buf, "\r\n\r\n");
    if (!body) {
        NR_LOG_ERR("%s", "enroll: malformed HTTP response (no header/body separator)");
        rc = NR_ERR_PROTO;
        goto out;
    }
    body += 4;

    /* Validate it looks like a certificate */
    if (strstr(body, "-----BEGIN CERTIFICATE-----") == NULL) {
        NR_LOG_ERR("%s", "enroll: response body is not a PEM certificate");
        rc = NR_ERR_PROTO;
        goto out;
    }

    size_t body_len = strlen(body);
    if (body_len >= cert_out_len) {
        NR_LOG_ERR("%s", "enroll: cert too large for output buffer");
        rc = NR_ERR_MEM;
        goto out;
    }

    memcpy(cert_out, body, body_len + 1);
    rc = NR_OK;
    NR_LOG_INFO("enroll: certificate received (%zu bytes)", body_len);

out:
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (fd >= 0) close(fd);
    if (buf) free(buf);
    return rc;
}
