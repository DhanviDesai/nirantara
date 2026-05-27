#define _POSIX_C_SOURCE 200809L

#include "enrollment/config.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_LISTEN_HOST "127.0.0.1"
#define DEFAULT_LISTEN_PORT 8080
#define DEFAULT_CERT_TTL_DAYS 365

static char *dup_env(const char *name) {
    const char *value = getenv(name);
    if (!value || value[0] == '\0') {
        return NULL;
    }
    return strdup(value);
}

static int parse_u16(const char *value, uint16_t *out) {
    char *end = NULL;
    unsigned long parsed;

    if (!value || value[0] == '\0') {
        return -1;
    }

    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed == 0 || parsed > 65535) {
        return -1;
    }

    *out = (uint16_t)parsed;
    return 0;
}

static int parse_long(const char *value, long *out) {
    char *end = NULL;
    long parsed;

    if (!value || value[0] == '\0') {
        return -1;
    }

    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed <= 0) {
        return -1;
    }

    *out = parsed;
    return 0;
}

static char *trim_line(char *line) {
    char *end;

    while (*line && isspace((unsigned char)*line)) {
        line++;
    }

    end = line + strlen(line);
    while (end > line && isspace((unsigned char)end[-1])) {
        *--end = '\0';
    }

    return line;
}

static int append_allowed_device(nr_enroll_config_t *cfg, const char *device_id) {
    char **next;
    char *copy;

    copy = strdup(device_id);
    if (!copy) {
        return -1;
    }

    next = realloc(cfg->allowed_devices,
                   (cfg->allowed_device_count + 1) * sizeof(*next));
    if (!next) {
        free(copy);
        return -1;
    }

    cfg->allowed_devices = next;
    cfg->allowed_devices[cfg->allowed_device_count++] = copy;
    return 0;
}

static int load_allowlist(nr_enroll_config_t *cfg, const char *path) {
    FILE *fp;
    char *line = NULL;
    size_t cap = 0;
    ssize_t nread;
    int rc = 0;

    fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "enrollment: open allowlist %s failed: %s\n",
                path, strerror(errno));
        return -1;
    }

    while ((nread = getline(&line, &cap, fp)) >= 0) {
        char *device_id;

        (void)nread;
        device_id = trim_line(line);
        if (device_id[0] == '\0' || device_id[0] == '#') {
            continue;
        }

        if (append_allowed_device(cfg, device_id) != 0) {
            rc = -1;
            break;
        }
    }

    free(line);
    fclose(fp);
    return rc;
}

static int require_string(char **dst, const char *env_name) {
    *dst = dup_env(env_name);
    if (!*dst) {
        fprintf(stderr, "enrollment: missing required env %s\n", env_name);
        return -1;
    }
    return 0;
}

int nr_enroll_config_load(nr_enroll_config_t *cfg) {
    const char *port_env;
    const char *ttl_env;
    const char *allow_any_env;
    const char *allowlist_path;

    memset(cfg, 0, sizeof(*cfg));

    cfg->listen_host = dup_env("NR_ENROLL_LISTEN_HOST");
    if (!cfg->listen_host) {
        cfg->listen_host = strdup(DEFAULT_LISTEN_HOST);
    }
    if (!cfg->listen_host) {
        return -1;
    }

    cfg->listen_port = DEFAULT_LISTEN_PORT;
    port_env = getenv("NR_ENROLL_PORT");
    if (port_env && parse_u16(port_env, &cfg->listen_port) != 0) {
        fprintf(stderr, "enrollment: invalid NR_ENROLL_PORT=%s\n", port_env);
        return -1;
    }

    cfg->cert_ttl_days = DEFAULT_CERT_TTL_DAYS;
    ttl_env = getenv("NR_ENROLL_CERT_TTL_DAYS");
    if (ttl_env && parse_long(ttl_env, &cfg->cert_ttl_days) != 0) {
        fprintf(stderr, "enrollment: invalid NR_ENROLL_CERT_TTL_DAYS=%s\n",
                ttl_env);
        return -1;
    }

    if (require_string(&cfg->ca_cert_path, "NR_ENROLL_CA_CERT") != 0 ||
        require_string(&cfg->kms_key_id, "NR_ENROLL_KMS_KEY_ID") != 0) {
        return -1;
    }

    cfg->aws_region = dup_env("AWS_REGION");
    if (!cfg->aws_region) {
        cfg->aws_region = dup_env("AWS_DEFAULT_REGION");
    }
    if (!cfg->aws_region) {
        fprintf(stderr, "enrollment: missing AWS_REGION or AWS_DEFAULT_REGION\n");
        return -1;
    }

    if (require_string(&cfg->aws_access_key_id, "AWS_ACCESS_KEY_ID") != 0 ||
        require_string(&cfg->aws_secret_access_key, "AWS_SECRET_ACCESS_KEY") != 0) {
        return -1;
    }
    cfg->aws_session_token = dup_env("AWS_SESSION_TOKEN");

    allow_any_env = getenv("NR_ENROLL_ALLOW_ANY_DEVICE");
    cfg->allow_any_device = allow_any_env && strcmp(allow_any_env, "1") == 0;

    allowlist_path = getenv("NR_ENROLL_DEVICE_ALLOWLIST");
    if (allowlist_path && allowlist_path[0] != '\0') {
        if (load_allowlist(cfg, allowlist_path) != 0) {
            return -1;
        }
    }

    if (!cfg->allow_any_device && cfg->allowed_device_count == 0) {
        fprintf(stderr,
                "enrollment: set NR_ENROLL_DEVICE_ALLOWLIST or "
                "NR_ENROLL_ALLOW_ANY_DEVICE=1 for local development\n");
        return -1;
    }

    if (cfg->allow_any_device) {
        fprintf(stderr,
                "enrollment: NR_ENROLL_ALLOW_ANY_DEVICE=1; "
                "do not use this in production\n");
    }

    return 0;
}

bool nr_enroll_device_allowed(const nr_enroll_config_t *cfg,
                              const char *device_id) {
    size_t i;

    if (cfg->allow_any_device) {
        return true;
    }

    for (i = 0; i < cfg->allowed_device_count; i++) {
        if (strcmp(cfg->allowed_devices[i], device_id) == 0) {
            return true;
        }
    }

    return false;
}

void nr_enroll_config_free(nr_enroll_config_t *cfg) {
    size_t i;

    if (!cfg) {
        return;
    }

    free(cfg->listen_host);
    free(cfg->ca_cert_path);
    free(cfg->kms_key_id);
    free(cfg->aws_region);
    free(cfg->aws_access_key_id);
    free(cfg->aws_secret_access_key);
    free(cfg->aws_session_token);

    for (i = 0; i < cfg->allowed_device_count; i++) {
        free(cfg->allowed_devices[i]);
    }
    free(cfg->allowed_devices);

    memset(cfg, 0, sizeof(*cfg));
}
