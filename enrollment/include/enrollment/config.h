#ifndef NIRANTARA_ENROLLMENT_CONFIG_H
#define NIRANTARA_ENROLLMENT_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    char    *listen_host;
    uint16_t listen_port;

    char    *ca_cert_path;
    char    *kms_key_id;
    char    *aws_region;
    char    *aws_access_key_id;
    char    *aws_secret_access_key;
    char    *aws_session_token;

    long     cert_ttl_days;

    bool     allow_any_device;
    char   **allowed_devices;
    size_t   allowed_device_count;
} nr_enroll_config_t;

int  nr_enroll_config_load(nr_enroll_config_t *cfg);
void nr_enroll_config_free(nr_enroll_config_t *cfg);
bool nr_enroll_device_allowed(const nr_enroll_config_t *cfg,
                              const char *device_id);

#endif /* NIRANTARA_ENROLLMENT_CONFIG_H */
