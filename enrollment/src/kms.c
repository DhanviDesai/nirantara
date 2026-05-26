#define _POSIX_C_SOURCE 200809L

#include "enrollment/kms.h"

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define KMS_TARGET_SIGN "TrentService.Sign"
#define KMS_SERVICE "kms"
#define KMS_HASH_SIZE SHA256_DIGEST_LENGTH

typedef struct {
    char *data;
    size_t len;
} nr_kms_buffer_t;

static int buffer_append(nr_kms_buffer_t *buf, const char *data, size_t len) {
    char *next = realloc(buf->data, buf->len + len + 1);
    if (!next) {
        return -1;
    }

    buf->data = next;
    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    buf->data[buf->len] = '\0';
    return 0;
}

static size_t curl_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t len = size * nmemb;
    nr_kms_buffer_t *buf = userdata;

    if (buffer_append(buf, ptr, len) != 0) {
        return 0;
    }

    return len;
}

static void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex_out) {
    static const char hex[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        hex_out[i * 2] = hex[bytes[i] >> 4];
        hex_out[i * 2 + 1] = hex[bytes[i] & 0x0f];
    }
    hex_out[len * 2] = '\0';
}

static void sha256_hex(const char *data, size_t len, char hex_out[65]) {
    unsigned char digest[KMS_HASH_SIZE];

    SHA256((const unsigned char *)data, len, digest);
    bytes_to_hex(digest, sizeof(digest), hex_out);
}

static int hmac_sha256(const unsigned char *key,
                       size_t key_len,
                       const char *data,
                       size_t data_len,
                       unsigned char out[KMS_HASH_SIZE]) {
    unsigned int out_len = 0;

    if (!HMAC(EVP_sha256(), key, (int)key_len, (const unsigned char *)data,
              data_len, out, &out_len)) {
        return -1;
    }

    return out_len == KMS_HASH_SIZE ? 0 : -1;
}

static int build_signing_key(const char *secret_key,
                             const char *date,
                             const char *region,
                             unsigned char out[KMS_HASH_SIZE]) {
    char key_seed[256];
    unsigned char k_date[KMS_HASH_SIZE];
    unsigned char k_region[KMS_HASH_SIZE];
    unsigned char k_service[KMS_HASH_SIZE];

    if (snprintf(key_seed, sizeof(key_seed), "AWS4%s", secret_key) >=
        (int)sizeof(key_seed)) {
        return -1;
    }

    if (hmac_sha256((const unsigned char *)key_seed, strlen(key_seed), date,
                    strlen(date), k_date) != 0 ||
        hmac_sha256(k_date, sizeof(k_date), region, strlen(region),
                    k_region) != 0 ||
        hmac_sha256(k_region, sizeof(k_region), KMS_SERVICE,
                    strlen(KMS_SERVICE), k_service) != 0 ||
        hmac_sha256(k_service, sizeof(k_service), "aws4_request",
                    strlen("aws4_request"), out) != 0) {
        return -1;
    }

    return 0;
}

static int base64_encode(const unsigned char *data, size_t len, char **out) {
    size_t encoded_len = 4 * ((len + 2) / 3);
    char *encoded = malloc(encoded_len + 1);

    if (!encoded) {
        return -1;
    }

    EVP_EncodeBlock((unsigned char *)encoded, data, (int)len);
    encoded[encoded_len] = '\0';
    *out = encoded;
    return 0;
}

static int base64_decode(const char *encoded,
                         unsigned char **out,
                         size_t *out_len) {
    size_t encoded_len = strlen(encoded);
    int decoded_len;
    unsigned char *decoded;
    size_t padding = 0;

    if (encoded_len == 0 || encoded_len % 4 != 0) {
        return -1;
    }

    decoded = malloc((encoded_len / 4) * 3);
    if (!decoded) {
        return -1;
    }

    decoded_len = EVP_DecodeBlock(decoded, (const unsigned char *)encoded,
                                  (int)encoded_len);
    if (decoded_len < 0) {
        free(decoded);
        return -1;
    }

    if (encoded_len >= 1 && encoded[encoded_len - 1] == '=') {
        padding++;
    }
    if (encoded_len >= 2 && encoded[encoded_len - 2] == '=') {
        padding++;
    }

    *out = decoded;
    *out_len = (size_t)decoded_len - padding;
    return 0;
}

static char *json_escape(const char *input) {
    size_t extra = 0;
    size_t i;
    char *out;
    char *dst;

    for (i = 0; input[i] != '\0'; i++) {
        if (input[i] == '"' || input[i] == '\\') {
            extra++;
        }
    }

    out = malloc(strlen(input) + extra + 1);
    if (!out) {
        return NULL;
    }

    dst = out;
    for (i = 0; input[i] != '\0'; i++) {
        if (input[i] == '"' || input[i] == '\\') {
            *dst++ = '\\';
        }
        *dst++ = input[i];
    }
    *dst = '\0';

    return out;
}

static char *json_get_string(const char *json, const char *key) {
    char needle[128];
    const char *pos;
    const char *colon;
    const char *start;
    char *out;
    size_t len = 0;

    if (snprintf(needle, sizeof(needle), "\"%s\"", key) >= (int)sizeof(needle)) {
        return NULL;
    }

    pos = strstr(json, needle);
    if (!pos) {
        return NULL;
    }

    colon = strchr(pos + strlen(needle), ':');
    if (!colon) {
        return NULL;
    }

    start = colon + 1;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }
    if (*start != '"') {
        return NULL;
    }
    start++;

    while (start[len] && start[len] != '"') {
        if (start[len] == '\\' && start[len + 1] != '\0') {
            len += 2;
        } else {
            len++;
        }
    }

    if (start[len] != '"') {
        return NULL;
    }

    out = malloc(len + 1);
    if (!out) {
        return NULL;
    }

    memcpy(out, start, len);
    out[len] = '\0';
    return out;
}

static int utc_timestamps(char date_out[9], char amz_date_out[17]) {
    time_t now = time(NULL);
    struct tm tm_utc;

    if (now == (time_t)-1 || !gmtime_r(&now, &tm_utc)) {
        return -1;
    }

    if (strftime(date_out, 9, "%Y%m%d", &tm_utc) != 8 ||
        strftime(amz_date_out, 17, "%Y%m%dT%H%M%SZ", &tm_utc) != 16) {
        return -1;
    }

    return 0;
}

static int build_json_body(const char *key_id,
                           const unsigned char digest[32],
                           char **body_out) {
    char *digest_b64 = NULL;
    char *escaped_key_id = NULL;
    char *body = NULL;
    int body_len;
    int rc = -1;

    if (base64_encode(digest, 32, &digest_b64) != 0) {
        goto out;
    }

    escaped_key_id = json_escape(key_id);
    if (!escaped_key_id) {
        goto out;
    }

    body_len = snprintf(NULL, 0,
                        "{\"KeyId\":\"%s\",\"Message\":\"%s\","
                        "\"MessageType\":\"DIGEST\","
                        "\"SigningAlgorithm\":\"ECDSA_SHA_256\"}",
                        escaped_key_id, digest_b64);
    if (body_len < 0) {
        goto out;
    }

    body = malloc((size_t)body_len + 1);
    if (!body) {
        goto out;
    }

    snprintf(body, (size_t)body_len + 1,
             "{\"KeyId\":\"%s\",\"Message\":\"%s\","
             "\"MessageType\":\"DIGEST\","
             "\"SigningAlgorithm\":\"ECDSA_SHA_256\"}",
             escaped_key_id, digest_b64);

    *body_out = body;
    body = NULL;
    rc = 0;

out:
    free(digest_b64);
    free(escaped_key_id);
    free(body);
    return rc;
}

static int build_authorization(const nr_enroll_config_t *cfg,
                               const char *host,
                               const char *body,
                               const char *date,
                               const char *amz_date,
                               char **auth_out) {
    char payload_hash[65];
    char canonical_headers[2048];
    char signed_headers[128];
    char canonical_request[4096];
    char canonical_request_hash[65];
    char credential_scope[256];
    char string_to_sign[1024];
    unsigned char signing_key[KMS_HASH_SIZE];
    unsigned char signature[KMS_HASH_SIZE];
    char signature_hex[65];
    char *auth = NULL;
    int canonical_headers_len;
    int signed_headers_len;
    int canonical_request_len;
    int credential_scope_len;
    int string_to_sign_len;
    int auth_len;

    sha256_hex(body, strlen(body), payload_hash);

    if (cfg->aws_session_token) {
        canonical_headers_len = snprintf(
            canonical_headers, sizeof(canonical_headers),
            "content-type:application/x-amz-json-1.1\n"
            "host:%s\n"
            "x-amz-date:%s\n"
            "x-amz-security-token:%s\n"
            "x-amz-target:%s\n",
            host, amz_date, cfg->aws_session_token, KMS_TARGET_SIGN);
        signed_headers_len = snprintf(
            signed_headers, sizeof(signed_headers),
            "content-type;host;x-amz-date;x-amz-security-token;x-amz-target");
    } else {
        canonical_headers_len = snprintf(
            canonical_headers, sizeof(canonical_headers),
            "content-type:application/x-amz-json-1.1\n"
            "host:%s\n"
            "x-amz-date:%s\n"
            "x-amz-target:%s\n",
            host, amz_date, KMS_TARGET_SIGN);
        signed_headers_len = snprintf(
            signed_headers, sizeof(signed_headers),
            "content-type;host;x-amz-date;x-amz-target");
    }

    if (canonical_headers_len < 0 ||
        canonical_headers_len >= (int)sizeof(canonical_headers) ||
        signed_headers_len < 0 ||
        signed_headers_len >= (int)sizeof(signed_headers)) {
        return -1;
    }

    canonical_request_len = snprintf(canonical_request,
                                     sizeof(canonical_request),
                                     "POST\n/\n\n%s\n%s\n%s",
                                     canonical_headers,
                                     signed_headers,
                                     payload_hash);
    if (canonical_request_len < 0 ||
        canonical_request_len >= (int)sizeof(canonical_request)) {
        return -1;
    }
    sha256_hex(canonical_request, strlen(canonical_request),
               canonical_request_hash);

    credential_scope_len = snprintf(credential_scope, sizeof(credential_scope),
                                    "%s/%s/%s/aws4_request",
                                    date, cfg->aws_region, KMS_SERVICE);
    if (credential_scope_len < 0 ||
        credential_scope_len >= (int)sizeof(credential_scope)) {
        return -1;
    }

    string_to_sign_len = snprintf(string_to_sign, sizeof(string_to_sign),
                                  "AWS4-HMAC-SHA256\n%s\n%s\n%s",
                                  amz_date, credential_scope,
                                  canonical_request_hash);
    if (string_to_sign_len < 0 ||
        string_to_sign_len >= (int)sizeof(string_to_sign)) {
        return -1;
    }

    if (build_signing_key(cfg->aws_secret_access_key, date, cfg->aws_region,
                          signing_key) != 0 ||
        hmac_sha256(signing_key, sizeof(signing_key), string_to_sign,
                    strlen(string_to_sign), signature) != 0) {
        return -1;
    }
    bytes_to_hex(signature, sizeof(signature), signature_hex);

    auth_len = snprintf(NULL, 0,
                        "AWS4-HMAC-SHA256 Credential=%s/%s, "
                        "SignedHeaders=%s, Signature=%s",
                        cfg->aws_access_key_id, credential_scope,
                        signed_headers, signature_hex);
    if (auth_len < 0) {
        return -1;
    }

    auth = malloc((size_t)auth_len + 1);
    if (!auth) {
        return -1;
    }

    snprintf(auth, (size_t)auth_len + 1,
             "AWS4-HMAC-SHA256 Credential=%s/%s, "
             "SignedHeaders=%s, Signature=%s",
             cfg->aws_access_key_id, credential_scope, signed_headers,
             signature_hex);

    *auth_out = auth;
    return 0;
}

int nr_kms_sign_sha256_digest(const nr_enroll_config_t *cfg,
                              const unsigned char digest[32],
                              unsigned char **sig_der_out,
                              size_t *sig_der_len_out) {
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    nr_kms_buffer_t response = {0};
    char *body = NULL;
    char *auth = NULL;
    char *signature_b64 = NULL;
    char host[256];
    char url[300];
    char date[9];
    char amz_date[17];
    char header_date[64];
    char header_auth[2048];
    char header_token[2048];
    long status = 0;
    CURLcode curl_rc;
    int rc = -1;

    if (snprintf(host, sizeof(host), "kms.%s.amazonaws.com",
                 cfg->aws_region) >= (int)sizeof(host) ||
        snprintf(url, sizeof(url), "https://%s/", host) >= (int)sizeof(url)) {
        return -1;
    }

    if (utc_timestamps(date, amz_date) != 0 ||
        build_json_body(cfg->kms_key_id, digest, &body) != 0 ||
        build_authorization(cfg, host, body, date, amz_date, &auth) != 0) {
        goto out;
    }

    curl = curl_easy_init();
    if (!curl) {
        goto out;
    }

    headers = curl_slist_append(headers,
                                "Content-Type: application/x-amz-json-1.1");
    headers = curl_slist_append(headers, "X-Amz-Target: " KMS_TARGET_SIGN);
    if (snprintf(header_date, sizeof(header_date), "X-Amz-Date: %s",
                 amz_date) >= (int)sizeof(header_date) ||
        snprintf(header_auth, sizeof(header_auth), "Authorization: %s",
                 auth) >= (int)sizeof(header_auth)) {
        goto out;
    }
    headers = curl_slist_append(headers, header_date);
    headers = curl_slist_append(headers, header_auth);

    if (cfg->aws_session_token) {
        if (snprintf(header_token, sizeof(header_token),
                     "X-Amz-Security-Token: %s",
                     cfg->aws_session_token) >= (int)sizeof(header_token)) {
            goto out;
        }
        headers = curl_slist_append(headers, header_token);
    }
    if (!headers) {
        goto out;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    curl_rc = curl_easy_perform(curl);
    if (curl_rc != CURLE_OK) {
        fprintf(stderr, "enrollment: KMS Sign failed: %s\n",
                curl_easy_strerror(curl_rc));
        goto out;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if (status != 200) {
        fprintf(stderr, "enrollment: KMS Sign HTTP %ld: %s\n",
                status, response.data ? response.data : "");
        goto out;
    }

    signature_b64 = json_get_string(response.data ? response.data : "",
                                    "Signature");
    if (!signature_b64) {
        fprintf(stderr, "enrollment: KMS response missing Signature\n");
        goto out;
    }

    if (base64_decode(signature_b64, sig_der_out, sig_der_len_out) != 0) {
        fprintf(stderr, "enrollment: invalid KMS Signature base64\n");
        goto out;
    }

    rc = 0;

out:
    free(body);
    free(auth);
    free(signature_b64);
    free(response.data);
    if (headers) {
        curl_slist_free_all(headers);
    }
    if (curl) {
        curl_easy_cleanup(curl);
    }
    return rc;
}
