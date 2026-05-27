#define _POSIX_C_SOURCE 200809L

#include "enrollment/http.h"
#include "enrollment/enrollment.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#ifdef __linux__
#include <sys/epoll.h>
#endif
#ifndef __linux__
#include <sys/select.h>
#endif
#include <sys/socket.h>
#include <unistd.h>

#define REQUEST_MAX_BYTES 65536
#define DEVICE_ID_MAX_BYTES 128
#define LISTEN_BACKLOG 128
#define MAX_CLIENTS 1024
#define EPOLL_MAX_EVENTS 64

typedef enum {
    CLIENT_READING = 0,
    CLIENT_WRITING = 1
} client_state_t;

typedef struct client_conn {
    int                  fd;
    client_state_t       state;
    char                *request;
    size_t               request_len;
    size_t               content_len;
    int                  have_content_len;
    char                *response;
    size_t               response_len;
    size_t               response_sent;
    struct client_conn  *next;
} client_conn_t;

static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0) {
        return -1;
    }

    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int build_response(int status,
                          const char *reason,
                          const char *content_type,
                          const char *body,
                          char **response_out,
                          size_t *response_len_out) {
    char headers[512];
    size_t body_len = body ? strlen(body) : 0;
    int headers_len;
    char *response;

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

    response = malloc((size_t)headers_len + body_len);
    if (!response) {
        return -1;
    }

    memcpy(response, headers, (size_t)headers_len);
    if (body_len > 0) {
        memcpy(response + headers_len, body, body_len);
    }

    *response_out = response;
    *response_len_out = (size_t)headers_len + body_len;
    return 0;
}

static int set_client_response(client_conn_t *client,
                               int status,
                               const char *reason,
                               const char *content_type,
                               const char *body) {
    char *response = NULL;
    size_t response_len = 0;

    if (build_response(status, reason, content_type, body, &response,
                       &response_len) != 0) {
        return -1;
    }

    free(client->response);
    client->response = response;
    client->response_len = response_len;
    client->response_sent = 0;
    client->state = CLIENT_WRITING;
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

static int request_complete(client_conn_t *client, int *malformed_out) {
    char *headers_end;
    size_t header_bytes;
    size_t expected_len;

    *malformed_out = 0;
    headers_end = strstr(client->request, "\r\n\r\n");
    if (!headers_end) {
        if (client->request_len >= REQUEST_MAX_BYTES) {
            *malformed_out = 1;
            return -1;
        }
        return 0;
    }

    header_bytes = (size_t)(headers_end + 4 - client->request);
    if (!client->have_content_len) {
        if (parse_content_length(client->request, headers_end,
                                 &client->content_len) != 0) {
            *malformed_out = 1;
            return -1;
        }
        client->have_content_len = 1;
    }

    if (client->content_len > REQUEST_MAX_BYTES ||
        header_bytes > REQUEST_MAX_BYTES - client->content_len) {
        *malformed_out = 1;
        return -1;
    }

    expected_len = header_bytes + client->content_len;
    return client->request_len >= expected_len ? 1 : 0;
}

static int process_request(client_conn_t *client,
                           const nr_enroll_config_t *cfg) {
    char *headers_end;
    char *device_id = NULL;
    char *cert_pem = NULL;
    const char *body;
    int rc = -1;

    client->request[client->request_len] = '\0';

    if (!request_line_is_enroll_post(client->request)) {
        rc = set_client_response(client, 404, "Not Found", "text/plain",
                                 "expected POST /enroll\n");
        goto out;
    }

    headers_end = strstr(client->request, "\r\n\r\n");
    if (!headers_end ||
        parse_content_length(client->request, headers_end,
                             &client->content_len) != 0) {
        rc = set_client_response(client, 400, "Bad Request", "text/plain",
                                 "missing Content-Length\n");
        goto out;
    }

    device_id = copy_header_value(client->request, headers_end, "X-Device-Id");
    if (!device_id || strlen(device_id) > DEVICE_ID_MAX_BYTES) {
        rc = set_client_response(client, 400, "Bad Request", "text/plain",
                                 "missing or invalid X-Device-Id\n");
        goto out;
    }

    body = headers_end + 4;
    if ((size_t)(client->request + client->request_len - body) <
        client->content_len) {
        rc = set_client_response(client, 400, "Bad Request", "text/plain",
                                 "incomplete request body\n");
        goto out;
    }

    if (nr_enrollment_issue_certificate(cfg, device_id, body, &cert_pem) != 0) {
        rc = set_client_response(client, 403, "Forbidden", "text/plain",
                                 "certificate enrollment failed\n");
        goto out;
    }

    rc = set_client_response(client, 200, "OK", "application/x-pem-file",
                             cert_pem);
    fprintf(stderr, "enrollment: issued certificate for device_id=%s\n",
            device_id);

out:
    free(cert_pem);
    free(device_id);
    return rc;
}

static client_conn_t *client_new(int fd) {
    client_conn_t *client = calloc(1, sizeof(*client));

    if (!client) {
        return NULL;
    }

    client->request = calloc(1, REQUEST_MAX_BYTES + 1);
    if (!client->request) {
        free(client);
        return NULL;
    }

    client->fd = fd;
    client->state = CLIENT_READING;
    return client;
}

static void client_free(client_conn_t *client) {
    if (!client) {
        return;
    }

    if (client->fd >= 0) {
        close(client->fd);
    }
    free(client->request);
    free(client->response);
    free(client);
}

static void client_list_add(client_conn_t **clients, client_conn_t *client) {
    client->next = *clients;
    *clients = client;
}

static void client_list_remove(client_conn_t **clients, client_conn_t *client) {
    client_conn_t **cur = clients;

    while (*cur) {
        if (*cur == client) {
            *cur = client->next;
            client->next = NULL;
            return;
        }
        cur = &(*cur)->next;
    }
}

static int read_client_ready(client_conn_t *client,
                             const nr_enroll_config_t *cfg) {
    for (;;) {
        ssize_t n;
        int malformed;
        int complete;

        if (client->request_len >= REQUEST_MAX_BYTES) {
            return set_client_response(client, 413, "Payload Too Large",
                                       "text/plain", "request too large\n");
        }

        n = recv(client->fd, client->request + client->request_len,
                 REQUEST_MAX_BYTES - client->request_len, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            return -1;
        }
        if (n == 0) {
            return client->request_len == 0
                       ? -1
                       : set_client_response(client, 400, "Bad Request",
                                             "text/plain",
                                             "malformed enrollment request\n");
        }

        client->request_len += (size_t)n;
        client->request[client->request_len] = '\0';

        complete = request_complete(client, &malformed);
        if (malformed) {
            return set_client_response(client, 400, "Bad Request",
                                       "text/plain",
                                       "malformed enrollment request\n");
        }
        if (complete < 0) {
            return -1;
        }
        if (complete > 0) {
            return process_request(client, cfg);
        }
    }
}

static int write_client_ready(client_conn_t *client) {
    while (client->response_sent < client->response_len) {
        ssize_t n = send(client->fd, client->response + client->response_sent,
                         client->response_len - client->response_sent, 0);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }

        client->response_sent += (size_t)n;
    }

    return 1;
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

    if (listen(fd, LISTEN_BACKLOG) != 0) {
        perror("enrollment: listen");
        close(fd);
        return -1;
    }

    if (set_nonblocking(fd) != 0) {
        perror("enrollment: fcntl");
        close(fd);
        return -1;
    }

    return fd;
}

static int accept_one_client(int listener, client_conn_t **clients,
                             size_t *client_count) {
    int client_fd = accept(listener, NULL, NULL);
    client_conn_t *client;

    if (client_fd < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        perror("enrollment: accept");
        return -1;
    }

    if (*client_count >= MAX_CLIENTS) {
        close(client_fd);
        return 0;
    }

    if (set_nonblocking(client_fd) != 0) {
        perror("enrollment: client fcntl");
        close(client_fd);
        return 0;
    }

    client = client_new(client_fd);
    if (!client) {
        close(client_fd);
        return 0;
    }

    client_list_add(clients, client);
    (*client_count)++;
    return 1;
}

static void close_client(client_conn_t **clients,
                         client_conn_t *client,
                         size_t *client_count) {
    client_list_remove(clients, client);
    if (*client_count > 0) {
        (*client_count)--;
    }
    client_free(client);
}

#ifdef __linux__
static int epoll_watch_client(int epfd, client_conn_t *client, int op) {
    struct epoll_event ev;

    memset(&ev, 0, sizeof(ev));
    ev.data.ptr = client;
    ev.events = client->state == CLIENT_READING ? EPOLLIN : EPOLLOUT;

    return epoll_ctl(epfd, op, client->fd, &ev);
}

static int serve_epoll(int listener, const nr_enroll_config_t *cfg) {
    int epfd;
    struct epoll_event ev;
    client_conn_t *clients = NULL;
    size_t client_count = 0;
    int rc = 1;

    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        perror("enrollment: epoll_create1");
        return 1;
    }

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.ptr = NULL;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listener, &ev) != 0) {
        perror("enrollment: epoll_ctl listener");
        goto out;
    }

    for (;;) {
        struct epoll_event events[EPOLL_MAX_EVENTS];
        int event_count;
        int i;

        event_count = epoll_wait(epfd, events, EPOLL_MAX_EVENTS, -1);
        if (event_count < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("enrollment: epoll_wait");
            goto out;
        }

        for (i = 0; i < event_count; i++) {
            client_conn_t *client = events[i].data.ptr;

            if (!client) {
                for (;;) {
                    int accepted = accept_one_client(listener, &clients,
                                                     &client_count);
                    if (accepted < 0) {
                        goto out;
                    }
                    if (accepted == 0) {
                        break;
                    }
                    if (epoll_watch_client(epfd, clients,
                                           EPOLL_CTL_ADD) != 0) {
                        perror("enrollment: epoll_ctl client add");
                        close_client(&clients, clients, &client_count);
                    }
                }
                continue;
            }

            if ((events[i].events & (EPOLLERR | EPOLLHUP)) != 0) {
                epoll_ctl(epfd, EPOLL_CTL_DEL, client->fd, NULL);
                close_client(&clients, client, &client_count);
                continue;
            }

            if (client->state == CLIENT_READING &&
                (events[i].events & EPOLLIN) != 0) {
                if (read_client_ready(client, cfg) != 0) {
                    epoll_ctl(epfd, EPOLL_CTL_DEL, client->fd, NULL);
                    close_client(&clients, client, &client_count);
                    continue;
                }
                if (client->state == CLIENT_WRITING &&
                    epoll_watch_client(epfd, client, EPOLL_CTL_MOD) != 0) {
                    perror("enrollment: epoll_ctl client mod");
                    epoll_ctl(epfd, EPOLL_CTL_DEL, client->fd, NULL);
                    close_client(&clients, client, &client_count);
                }
            } else if (client->state == CLIENT_WRITING &&
                       (events[i].events & EPOLLOUT) != 0) {
                int write_rc = write_client_ready(client);
                if (write_rc != 0) {
                    epoll_ctl(epfd, EPOLL_CTL_DEL, client->fd, NULL);
                    close_client(&clients, client, &client_count);
                }
            }
        }
    }

out:
    while (clients) {
        close_client(&clients, clients, &client_count);
    }
    close(epfd);
    return rc;
}
#endif

#ifndef __linux__
static int serve_select(int listener, const nr_enroll_config_t *cfg) {
    client_conn_t *clients = NULL;
    size_t client_count = 0;
    int rc = 1;

    for (;;) {
        fd_set readfds;
        fd_set writefds;
        client_conn_t *client;
        int max_fd = listener;
        int ready;

        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_SET(listener, &readfds);

        for (client = clients; client; client = client->next) {
            if (client->fd >= FD_SETSIZE) {
                close_client(&clients, client, &client_count);
                break;
            }
            if (client->state == CLIENT_READING) {
                FD_SET(client->fd, &readfds);
            } else {
                FD_SET(client->fd, &writefds);
            }
            if (client->fd > max_fd) {
                max_fd = client->fd;
            }
        }

        ready = select(max_fd + 1, &readfds, &writefds, NULL, NULL);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("enrollment: select");
            goto out;
        }

        if (FD_ISSET(listener, &readfds)) {
            for (;;) {
                int accepted = accept_one_client(listener, &clients,
                                                 &client_count);
                if (accepted < 0) {
                    goto out;
                }
                if (accepted == 0) {
                    break;
                }
            }
        }

        client = clients;
        while (client) {
            client_conn_t *next = client->next;

            if (client->state == CLIENT_READING &&
                FD_ISSET(client->fd, &readfds)) {
                if (read_client_ready(client, cfg) != 0) {
                    close_client(&clients, client, &client_count);
                }
            } else if (client->state == CLIENT_WRITING &&
                       FD_ISSET(client->fd, &writefds)) {
                int write_rc = write_client_ready(client);
                if (write_rc != 0) {
                    close_client(&clients, client, &client_count);
                }
            }

            client = next;
        }
    }

out:
    while (clients) {
        close_client(&clients, clients, &client_count);
    }
    return rc;
}
#endif

int nr_enrollment_serve(const nr_enroll_config_t *cfg) {
    int listener;
    int rc;

    signal(SIGPIPE, SIG_IGN);

    listener = bind_listener(cfg);
    if (listener < 0) {
        return 1;
    }

    fprintf(stderr,
#ifdef __linux__
            "enrollment: listening on %s:%u with epoll\n",
#else
            "enrollment: listening on %s:%u with select\n",
#endif
            cfg->listen_host, cfg->listen_port);

#ifdef __linux__
    rc = serve_epoll(listener, cfg);
#else
    rc = serve_select(listener, cfg);
#endif

    close(listener);
    return rc;
}
