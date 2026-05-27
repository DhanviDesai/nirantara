#ifndef NIRANTARA_ENROLLMENT_KMS_H
#define NIRANTARA_ENROLLMENT_KMS_H

#include "enrollment/config.h"

#include <stddef.h>

int nr_kms_sign_sha256_digest(const nr_enroll_config_t *cfg,
                              const unsigned char digest[32],
                              unsigned char **sig_der_out,
                              size_t *sig_der_len_out);

#endif /* NIRANTARA_ENROLLMENT_KMS_H */
