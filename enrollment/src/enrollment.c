#define _POSIX_C_SOURCE 200809L

#include "enrollment/enrollment.h"
#include "enrollment/kms.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_DEVICE_ID_LEN 128

static int valid_device_id(const char *device_id) {
    size_t i;
    size_t len;

    if (!device_id) {
        return 0;
    }

    len = strlen(device_id);
    if (len == 0 || len > MAX_DEVICE_ID_LEN) {
        return 0;
    }

    for (i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)device_id[i];
        if (!isalnum(ch) && ch != '-' && ch != '_' && ch != '.' && ch != ':') {
            return 0;
        }
    }

    return 1;
}

static X509 *load_ca_cert(const char *path) {
    FILE *fp;
    X509 *cert;

    fp = fopen(path, "r");
    if (!fp) {
        perror("enrollment: open CA cert");
        return NULL;
    }

    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!cert) {
        fprintf(stderr, "enrollment: failed to parse CA certificate PEM\n");
    }
    return cert;
}

static X509_REQ *load_csr(const char *csr_pem) {
    BIO *bio;
    X509_REQ *csr;

    bio = BIO_new_mem_buf(csr_pem, -1);
    if (!bio) {
        return NULL;
    }

    csr = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return csr;
}

static int verify_csr(X509_REQ *csr, EVP_PKEY **pubkey_out) {
    EVP_PKEY *pubkey;
    int verify_rc;

    pubkey = X509_REQ_get_pubkey(csr);
    if (!pubkey) {
        return -1;
    }

    verify_rc = X509_REQ_verify(csr, pubkey);
    if (verify_rc != 1) {
        EVP_PKEY_free(pubkey);
        return -1;
    }

    *pubkey_out = pubkey;
    return 0;
}

static X509_NAME *build_subject_name(const char *device_id) {
    X509_NAME *name;

    name = X509_NAME_new();
    if (!name) {
        return NULL;
    }

    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    (const unsigned char *)device_id, -1, -1,
                                    0) ||
        !X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                    (const unsigned char *)"Nirantara", -1,
                                    -1, 0)) {
        X509_NAME_free(name);
        return NULL;
    }

    return name;
}

static int set_random_serial(X509 *cert) {
    unsigned char serial_bytes[16];
    BIGNUM *serial_bn = NULL;
    ASN1_INTEGER *serial_asn1 = NULL;
    int rc = -1;

    if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) {
        return -1;
    }
    serial_bytes[0] &= 0x7f;
    if (serial_bytes[0] == 0) {
        serial_bytes[0] = 1;
    }

    serial_bn = BN_bin2bn(serial_bytes, sizeof(serial_bytes), NULL);
    if (!serial_bn) {
        goto out;
    }

    serial_asn1 = BN_to_ASN1_INTEGER(serial_bn, NULL);
    if (!serial_asn1) {
        goto out;
    }

    if (X509_set_serialNumber(cert, serial_asn1) != 1) {
        goto out;
    }

    rc = 0;

out:
    ASN1_INTEGER_free(serial_asn1);
    BN_free(serial_bn);
    return rc;
}

static int add_extension(X509 *cert,
                         X509 *issuer,
                         int nid,
                         const char *value) {
    X509V3_CTX ctx;
    X509_EXTENSION *ext;

    X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *)value);
    if (!ext) {
        return -1;
    }

    if (X509_add_ext(cert, ext, -1) != 1) {
        X509_EXTENSION_free(ext);
        return -1;
    }

    X509_EXTENSION_free(ext);
    return 0;
}

static EVP_PKEY *generate_algorithm_seed_key(void) {
    EVP_PKEY_CTX *key_ctx = NULL;
    EVP_PKEY *key = NULL;

    key_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!key_ctx) {
        goto out;
    }

    if (EVP_PKEY_keygen_init(key_ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(key_ctx,
                                               NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(key_ctx, &key) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }

out:
    EVP_PKEY_CTX_free(key_ctx);
    return key;
}

static X509 *build_unsigned_cert(const nr_enroll_config_t *cfg,
                                 const char *device_id,
                                 X509 *ca_cert,
                                 EVP_PKEY *device_pubkey) {
    X509 *cert = NULL;
    X509_NAME *subject = NULL;
    EVP_PKEY *seed_key = NULL;

    cert = X509_new();
    if (!cert) {
        goto err;
    }

    if (X509_set_version(cert, 2) != 1 ||
        set_random_serial(cert) != 0 ||
        X509_set_issuer_name(cert, X509_get_subject_name(ca_cert)) != 1 ||
        X509_set_pubkey(cert, device_pubkey) != 1) {
        goto err;
    }

    subject = build_subject_name(device_id);
    if (!subject || X509_set_subject_name(cert, subject) != 1) {
        goto err;
    }

    if (!X509_gmtime_adj(X509_getm_notBefore(cert), 0) ||
        !X509_gmtime_adj(X509_getm_notAfter(cert),
                         cfg->cert_ttl_days * 24L * 60L * 60L)) {
        goto err;
    }

    if (add_extension(cert, ca_cert, NID_basic_constraints,
                      "critical,CA:FALSE") != 0 ||
        add_extension(cert, ca_cert, NID_key_usage,
                      "critical,digitalSignature") != 0 ||
        add_extension(cert, ca_cert, NID_ext_key_usage, "clientAuth") != 0 ||
        add_extension(cert, ca_cert, NID_subject_key_identifier, "hash") != 0 ||
        add_extension(cert, ca_cert, NID_authority_key_identifier,
                      "keyid:always") != 0) {
        goto err;
    }

    /*
     * X509_sign sets the TBSCertificate and outer signatureAlgorithm fields.
     * The resulting local signature is discarded; the final certificate bytes
     * are assembled with the KMS signature over the same TBSCertificate DER.
     */
    seed_key = generate_algorithm_seed_key();
    if (!seed_key || X509_sign(cert, seed_key, EVP_sha256()) <= 0) {
        goto err;
    }

    X509_NAME_free(subject);
    EVP_PKEY_free(seed_key);
    return cert;

err:
    X509_NAME_free(subject);
    EVP_PKEY_free(seed_key);
    X509_free(cert);
    return NULL;
}

static int der_len_size(size_t len) {
    int bytes = 0;
    size_t tmp = len;

    if (len < 128) {
        return 1;
    }

    while (tmp > 0) {
        bytes++;
        tmp >>= 8;
    }

    return 1 + bytes;
}

static unsigned char *write_der_len(unsigned char *p, size_t len) {
    int bytes;
    int i;

    if (len < 128) {
        *p++ = (unsigned char)len;
        return p;
    }

    bytes = der_len_size(len) - 1;
    *p++ = (unsigned char)(0x80 | bytes);
    for (i = bytes - 1; i >= 0; i--) {
        *p++ = (unsigned char)(len >> (i * 8));
    }

    return p;
}

static int encode_alg_der(unsigned char **alg_der_out, int *alg_der_len_out) {
    X509_ALGOR *alg = NULL;
    unsigned char *alg_der = NULL;
    unsigned char *p;
    int alg_der_len;
    int rc = -1;

    alg = X509_ALGOR_new();
    if (!alg) {
        goto out;
    }

    X509_ALGOR_set0(alg, OBJ_nid2obj(NID_ecdsa_with_SHA256), V_ASN1_UNDEF,
                    NULL);

    alg_der_len = i2d_X509_ALGOR(alg, NULL);
    if (alg_der_len <= 0) {
        goto out;
    }

    alg_der = malloc((size_t)alg_der_len);
    if (!alg_der) {
        goto out;
    }

    p = alg_der;
    if (i2d_X509_ALGOR(alg, &p) != alg_der_len) {
        goto out;
    }

    *alg_der_out = alg_der;
    *alg_der_len_out = alg_der_len;
    alg_der = NULL;
    rc = 0;

out:
    free(alg_der);
    X509_ALGOR_free(alg);
    return rc;
}

static int encode_signature_bitstring_der(const unsigned char *sig_der,
                                          size_t sig_der_len,
                                          unsigned char **bit_der_out,
                                          int *bit_der_len_out) {
    ASN1_BIT_STRING *bit = NULL;
    unsigned char *bit_der = NULL;
    unsigned char *p;
    int bit_der_len;
    int rc = -1;

    bit = ASN1_BIT_STRING_new();
    if (!bit) {
        goto out;
    }

    if (ASN1_BIT_STRING_set(bit, sig_der, (int)sig_der_len) != 1) {
        goto out;
    }
    bit->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT | 0x07);

    bit_der_len = i2d_ASN1_BIT_STRING(bit, NULL);
    if (bit_der_len <= 0) {
        goto out;
    }

    bit_der = malloc((size_t)bit_der_len);
    if (!bit_der) {
        goto out;
    }

    p = bit_der;
    if (i2d_ASN1_BIT_STRING(bit, &p) != bit_der_len) {
        goto out;
    }

    *bit_der_out = bit_der;
    *bit_der_len_out = bit_der_len;
    bit_der = NULL;
    rc = 0;

out:
    free(bit_der);
    ASN1_BIT_STRING_free(bit);
    return rc;
}

static int assemble_certificate_der(const unsigned char *tbs_der,
                                    int tbs_der_len,
                                    const unsigned char *sig_der,
                                    size_t sig_der_len,
                                    unsigned char **cert_der_out,
                                    size_t *cert_der_len_out) {
    unsigned char *alg_der = NULL;
    unsigned char *bit_der = NULL;
    unsigned char *cert_der = NULL;
    unsigned char *p;
    int alg_der_len = 0;
    int bit_der_len = 0;
    size_t content_len;
    size_t cert_der_len;
    int rc = -1;

    if (encode_alg_der(&alg_der, &alg_der_len) != 0 ||
        encode_signature_bitstring_der(sig_der, sig_der_len, &bit_der,
                                       &bit_der_len) != 0) {
        goto out;
    }

    content_len = (size_t)tbs_der_len + (size_t)alg_der_len +
                  (size_t)bit_der_len;
    cert_der_len = 1 + (size_t)der_len_size(content_len) + content_len;
    cert_der = malloc(cert_der_len);
    if (!cert_der) {
        goto out;
    }

    p = cert_der;
    *p++ = 0x30;
    p = write_der_len(p, content_len);
    memcpy(p, tbs_der, (size_t)tbs_der_len);
    p += tbs_der_len;
    memcpy(p, alg_der, (size_t)alg_der_len);
    p += alg_der_len;
    memcpy(p, bit_der, (size_t)bit_der_len);

    *cert_der_out = cert_der;
    *cert_der_len_out = cert_der_len;
    cert_der = NULL;
    rc = 0;

out:
    free(alg_der);
    free(bit_der);
    free(cert_der);
    return rc;
}

static int der_to_pem(const unsigned char *der, size_t der_len, char **pem_out) {
    BIO *bio = NULL;
    BUF_MEM *mem = NULL;
    char *pem = NULL;
    int rc = -1;

    bio = BIO_new(BIO_s_mem());
    if (!bio) {
        goto out;
    }

    if (PEM_write_bio(bio, "CERTIFICATE", "", der, (long)der_len) != 1) {
        goto out;
    }

    BIO_get_mem_ptr(bio, &mem);
    pem = malloc(mem->length + 1);
    if (!pem) {
        goto out;
    }

    memcpy(pem, mem->data, mem->length);
    pem[mem->length] = '\0';
    *pem_out = pem;
    pem = NULL;
    rc = 0;

out:
    free(pem);
    BIO_free(bio);
    return rc;
}

static int verify_issued_cert(const unsigned char *der,
                              size_t der_len,
                              X509 *ca_cert) {
    const unsigned char *p = der;
    X509 *cert = NULL;
    EVP_PKEY *ca_pubkey = NULL;
    int rc = -1;

    cert = d2i_X509(NULL, &p, (long)der_len);
    if (!cert) {
        goto out;
    }

    ca_pubkey = X509_get_pubkey(ca_cert);
    if (!ca_pubkey) {
        goto out;
    }

    if (X509_verify(cert, ca_pubkey) != 1) {
        fprintf(stderr,
                "enrollment: issued cert did not verify with configured CA; "
                "does NR_ENROLL_CA_CERT match NR_ENROLL_KMS_KEY_ID?\n");
        goto out;
    }

    rc = 0;

out:
    EVP_PKEY_free(ca_pubkey);
    X509_free(cert);
    return rc;
}

int nr_enrollment_issue_certificate(const nr_enroll_config_t *cfg,
                                    const char *device_id,
                                    const char *csr_pem,
                                    char **cert_pem_out) {
    X509 *ca_cert = NULL;
    X509_REQ *csr = NULL;
    EVP_PKEY *device_pubkey = NULL;
    X509 *unsigned_cert = NULL;
    unsigned char *tbs_der = NULL;
    unsigned char *tbs_p = NULL;
    unsigned char tbs_digest[SHA256_DIGEST_LENGTH];
    unsigned char *sig_der = NULL;
    unsigned char *cert_der = NULL;
    int tbs_der_len;
    size_t sig_der_len = 0;
    size_t cert_der_len = 0;
    int rc = -1;

    if (!valid_device_id(device_id)) {
        fprintf(stderr, "enrollment: invalid device_id\n");
        return -1;
    }
    if (!nr_enroll_device_allowed(cfg, device_id)) {
        fprintf(stderr, "enrollment: device_id not allowed: %s\n", device_id);
        return -1;
    }

    ca_cert = load_ca_cert(cfg->ca_cert_path);
    csr = load_csr(csr_pem);
    if (!ca_cert || !csr) {
        goto out;
    }

    if (verify_csr(csr, &device_pubkey) != 0) {
        fprintf(stderr, "enrollment: CSR signature verification failed\n");
        goto out;
    }

    unsigned_cert = build_unsigned_cert(cfg, device_id, ca_cert, device_pubkey);
    if (!unsigned_cert) {
        goto out;
    }

    tbs_der_len = i2d_re_X509_tbs(unsigned_cert, NULL);
    if (tbs_der_len <= 0) {
        goto out;
    }

    tbs_der = malloc((size_t)tbs_der_len);
    if (!tbs_der) {
        goto out;
    }
    tbs_p = tbs_der;
    if (i2d_re_X509_tbs(unsigned_cert, &tbs_p) != tbs_der_len) {
        goto out;
    }

    SHA256(tbs_der, (size_t)tbs_der_len, tbs_digest);
    if (nr_kms_sign_sha256_digest(cfg, tbs_digest, &sig_der,
                                  &sig_der_len) != 0) {
        goto out;
    }

    if (assemble_certificate_der(tbs_der, tbs_der_len, sig_der, sig_der_len,
                                 &cert_der, &cert_der_len) != 0 ||
        verify_issued_cert(cert_der, cert_der_len, ca_cert) != 0 ||
        der_to_pem(cert_der, cert_der_len, cert_pem_out) != 0) {
        goto out;
    }

    rc = 0;

out:
    free(tbs_der);
    free(sig_der);
    free(cert_der);
    X509_free(unsigned_cert);
    EVP_PKEY_free(device_pubkey);
    X509_REQ_free(csr);
    X509_free(ca_cert);
    return rc;
}
