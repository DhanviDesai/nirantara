#define _POSIX_C_SOURCE 200809L

#include "enrollment/http.h"
#include "enrollment/enrollment.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#define REQUEST_MAX_BYTES 65536
#define DEVICE_ID_MAX_BYTES 128

static int send_all(int fd, const char *buf, size_t len) {
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        sent += (size_t)n;
    }

    return 0;
}

static int send_response(int fd,
                         int status,
                         const char *reason,
                         const char *content_type,
                         const char *body) {
    char headers[512];
    size_t body_len = body ? strlen(body) : 0;
    int headers_len;

    headers_len = snprintf(headers, sizeof(headers),
                           "HTTP/1.1 %d %s\r\n"
                           "Content-Type: %s\r\n"
                           "Content-Length: %zu\r\n"
                           "Connection: close\r\n"
                           "\r\n",
                           status, reason, content_type, body_len);
    if (headers_len < 0 || headers_len >= (int)sizeof(headers)) {
        return -1;
    }

    if (send_all(fd, headers, (size_t)headers_len) != 0) {
        return -1;
    }

    if (body_len > 0 && send_all(fd, body, body_len) != 0) {
        return -1;
    }

    return 0;
}

static int header_name_matches(const char *line,
                               const char *line_end,
                               const char *name) {
    size_t name_len = strlen(name);

    if ((size_t)(line_end - line) <= name_len || line[name_len] != ':') {
        return 0;
    }

    return strncasecmp(line, name, name_len) == 0;
}

static char *copy_header_value(const char *headers,
                               const char *headers_end,
                               const char *name) {
    const char *line = headers;

    while (line < headers_end) {
        const char *line_end = strstr(line, "\r\n");
        const char *value;
        const char *value_end;
        size_t len;
        char *out;

        if (!line_end || line_end > headers_end) {
            break;
        }

        if (header_name_matches(line, line_end, name)) {
            value = line + strlen(name) + 1;
            while (value < line_end && (*value == ' ' || *value == '\t')) {
                value++;
            }
            value_end = line_end;
            while (value_end > value &&
                   (value_end[-1] == ' ' || value_end[-1] == '\t')) {
                value_end--;
            }

            len = (size_t)(value_end - value);
            out = malloc(len + 1);
            if (!out) {
                return NULL;
            }

            memcpy(out, value, len);
            out[len] = '\0';
            return out;
        }

        line = line_end + 2;
    }

    return NULL;
}

static int parse_content_length(const char *headers,
                                const char *headers_end,
                                size_t *content_len_out) {
    char *value = copy_header_value(headers, headers_end, "Content-Length");
    char *end = NULL;
    unsigned long parsed;

    if (!value) {
        return -1;
    }

    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || !end || *end != '\0' || parsed > REQUEST_MAX_BYTES) {
        free(value);
        return -1;
    }

    *content_len_out = parsed;
    free(value);
    return 0;
}

static int read_request(int fd, char **request_out, size_t *request_len_out) {
    char *buf = calloc(1, REQUEST_MAX_BYTES + 1);
    size_t total = 0;
    size_t content_len = 0;
    int have_content_len = 0;

    if (!buf) {
        return -1;
    }

    while (total < REQUEST_MAX_BYTES) {
        char *headers_end;
        ssize_t n = recv(fd, buf + total, REQUEST_MAX_BYTES - total, 0);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            free(buf);
            return -1;
        }
        if (n == 0) {
            break;
        }

        total += (size_t)n;
        buf[total] = '\0';

        headers_end = strstr(buf, "\r\n\r\n");
        if (headers_end) {
            size_t header_bytes = (size_t)(headers_end + 4 - buf);
            if (!have_content_len) {
                if (parse_content_length(buf, headers_end, &content_len) != 0) {
                    free(buf);
                    return -1;
                }
                have_content_len = 1;
            }

            if (total >= header_bytes + content_len) {
                *request_out = buf;
                *request_len_out = header_bytes + content_len;
                return 0;
            }
        }
    }

    free(buf);
    return -1;
}

static int request_line_is_enroll_post(const char *request) {
    const char *line_end = strstr(request, "\r\n");
    size_t line_len;

    if (!line_end) {
        return 0;
    }

    line_len = (size_t)(line_end - request);
    return line_len >= strlen("POST /enroll HTTP/1.1") &&
           strncmp(request, "POST /enroll ", strlen("POST /enroll ")) == 0;
}

static void handle_client(int fd, const nr_enroll_config_t *cfg) {
    char *request = NULL;
    char *headers_end;
    char *device_id = NULL;
    char *cert_pem = NULL;
    size_t request_len = 0;
    size_t content_len = 0;
    const char *body;

    if (read_request(fd, &request, &request_len) != 0) {
        send_response(fd, 400, "Bad Request", "text/plain",
                      "malformed enrollment request\n");
        goto out;
    }
    request[request_len] = '\0';

    if (!request_line_is_enroll_post(request)) {
        send_response(fd, 404, "Not Found", "text/plain",
                      "expected POST /enroll\n");
        goto out;
    }

    headers_end = strstr(request, "\r\n\r\n");
    if (!headers_end ||
        parse_content_length(request, headers_end, &content_len) != 0) {
        send_response(fd, 400, "Bad Request", "text/plain",
                      "missing Content-Length\n");
        goto out;
    }

    device_id = copy_header_value(request, headers_end, "X-Device-Id");
    if (!device_id || strlen(device_id) > DEVICE_ID_MAX_BYTES) {
        send_response(fd, 400, "Bad Request", "text/plain",
                      "missing or invalid X-Device-Id\n");
        goto out;
    }

    body = headers_end + 4;
    if ((size_t)(request + request_len - body) < content_len) {
        send_response(fd, 400, "Bad Request", "text/plain",
                      "incomplete request body\n");
        goto out;
    }

    if (nr_enrollment_issue_certificate(cfg, device_id, body, &cert_pem) != 0) {
        send_response(fd, 403, "Forbidden", "text/plain",
                      "certificate enrollment failed\n");
        goto out;
    }

    send_response(fd, 200, "OK", "application/x-pem-file", cert_pem);
    fprintf(stderr, "enrollment: issued certificate for device_id=%s\n",
            device_id);

out:
    free(cert_pem);
    free(device_id);
    free(request);
}

static int bind_listener(const nr_enroll_config_t *cfg) {
    int fd;
    int yes = 1;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("enrollment: socket");
        return -1;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) != 0) {
        perror("enrollment: setsockopt");
        close(fd);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(cfg->listen_port);
    if (inet_pton(AF_INET, cfg->listen_host, &addr.sin_addr) != 1) {
        fprintf(stderr, "enrollment: listen host must be an IPv4 address: %s\n",
                cfg->listen_host);
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("enrollment: bind");
        close(fd);
        return -1;
    }

    if (listen(fd, 32) != 0) {
        perror("enrollment: listen");
        close(fd);
        return -1;
    }

    return fd;
}

int nr_enrollment_serve(const nr_enroll_config_t *cfg) {
    int listener;

    signal(SIGPIPE, SIG_IGN);

    listener = bind_listener(cfg);
    if (listener < 0) {
        return 1;
    }

    fprintf(stderr, "enrollment: listening on %s:%u\n",
            cfg->listen_host, cfg->listen_port);

    for (;;) {
        int client = accept(listener, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("enrollment: accept");
            close(listener);
            return 1;
        }

        handle_client(client, cfg);
        close(client);
    }
}
