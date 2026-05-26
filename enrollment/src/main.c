#include "enrollment/config.h"
#include "enrollment/http.h"

#include <curl/curl.h>
#include <stdio.h>

int main(void) {
    nr_enroll_config_t cfg;
    int rc;

    if (nr_enroll_config_load(&cfg) != 0) {
        nr_enroll_config_free(&cfg);
        return 1;
    }

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
        fprintf(stderr, "enrollment: curl_global_init failed\n");
        nr_enroll_config_free(&cfg);
        return 1;
    }

    rc = nr_enrollment_serve(&cfg);

    curl_global_cleanup();
    nr_enroll_config_free(&cfg);
    return rc;
}
