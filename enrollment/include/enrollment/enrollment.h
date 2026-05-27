#ifndef NIRANTARA_ENROLLMENT_H
#define NIRANTARA_ENROLLMENT_H

#include "enrollment/config.h"

int nr_enrollment_issue_certificate(const nr_enroll_config_t *cfg,
                                    const char *device_id,
                                    const char *csr_pem,
                                    char **cert_pem_out);

#endif /* NIRANTARA_ENROLLMENT_H */
