/*
 * Developed by Nicolas Martyanoff
 * Copyright (c) 2015 Celticom
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <inttypes.h>
#include <signal.h>

#include "http.h"

struct httpex {
    struct io_base *base;
    struct http_client *client;
    struct c_ptr_vector *uris;
    size_t nb_responses;
    bool do_exit;
};

static void httpex_die(const char *, ...)
    __attribute__ ((format(printf, 1, 2), noreturn));

static void httpex_on_signal(int, void *);

static void httpex_on_client_event(struct http_client *,
                                   enum http_client_event, void *, void *);
static void httpex_on_client_response(struct http_client *,
                                      struct http_response *, void *);

static struct httpex httpex;

int
main(int argc, char **argv) {
    struct c_command_line *cmdline;
    const char *host, *port_string;
    uint16_t port;
    bool use_ssl;
    const char *ca_path;

    cmdline = c_command_line_new();

    c_command_line_add_flag(cmdline, "s", "ssl", "use ssl");
    c_command_line_add_option(cmdline, NULL, "ca", "the ssl ca certificate",
                              "path", NULL);

    c_command_line_add_argument(cmdline, "the host to connect to", "host");
    c_command_line_add_argument(cmdline, "the port to connect on", "port");
    c_command_line_add_trailing_arguments(cmdline, "the list of uri targets",
                                          "uri");

    if (c_command_line_parse(cmdline, argc, argv) == -1)
        httpex_die("%s", c_get_error());

    host = c_command_line_argument_value(cmdline, 0);

    port_string = c_command_line_argument_value(cmdline, 1);
    if (c_parse_u16(port_string, &port, NULL) == -1)
        httpex_die("invalid port number: %s", c_get_error());

    httpex.uris = c_ptr_vector_new();
    for (size_t i = 0; i < c_command_line_nb_trailing_arguments(cmdline); i++) {
        struct http_uri *uri;
        const char *string;

        string = c_command_line_trailing_argument_value(cmdline, i);
        uri = http_uri_parse(string);
        if (!uri)
            httpex_die("invalid uri: %s", c_get_error());

        c_ptr_vector_append(httpex.uris, uri);
    }

    use_ssl = c_command_line_is_option_set(cmdline, "ssl");
    if (use_ssl)
        ca_path = c_command_line_option_value(cmdline, "ca");

    if (use_ssl)
        io_ssl_initialize();

    httpex.base = io_base_new();

    if (io_base_watch_signal(httpex.base, SIGINT, httpex_on_signal, NULL) == -1)
        httpex_die("cannot watch signal: %s", c_get_error());
    if (io_base_watch_signal(httpex.base, SIGTERM, httpex_on_signal, NULL) == -1)
        httpex_die("cannot watch signal: %s", c_get_error());

    httpex.client = http_client_new(httpex.base);
    http_client_set_event_cb(httpex.client, httpex_on_client_event, NULL);

#if 0
    if (use_ssl) {
        struct io_ssl_cfg cfg;

        memset(&cfg, 0, sizeof(struct io_ssl_cfg));
        cfg.cert_path = cert_path;
        cfg.key_path = key_path;

        if (io_tcp_server_enable_ssl(httpex.server, &cfg) == -1)
            httpex_die("cannot enable ssl: %s", c_get_error());
    }
#endif

    if (http_client_connect(httpex.client, host, port) == -1)
        httpex_die("cannot connect to %s:%u: %s", host, port, c_get_error());

    while (!httpex.do_exit) {
        if (io_base_read_events(httpex.base) == -1)
            httpex_die("cannot read events: %s", c_get_error());
    }

    for (size_t i = 0; i < c_ptr_vector_length(httpex.uris); i++)
        http_uri_delete(c_ptr_vector_entry(httpex.uris, i));
    c_ptr_vector_delete(httpex.uris);

    http_client_delete(httpex.client);
    io_base_delete(httpex.base);

    if (use_ssl)
        io_ssl_shutdown();

    c_command_line_delete(cmdline);
    return 0;
}

void
httpex_die(const char *fmt, ...) {
    va_list ap;

    fprintf(stderr, "fatal error: ");

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    putc('\n', stderr);
    exit(1);
}

static void
httpex_on_signal(int signo, void *arg) {
    printf("signal %d received\n", signo);

    switch (signo) {
    case SIGINT:
    case SIGTERM:
        http_client_disconnect(httpex.client);
        httpex.do_exit = true;
        break;
    }
}

static void
httpex_on_client_event(struct http_client *client,
                       enum http_client_event event, void *data,
                       void *arg) {
    switch (event) {
    case HTTP_CLIENT_EVENT_TRACE:
        printf("%s\n", (char *)data);
        break;

    case HTTP_CLIENT_EVENT_ERROR:
        fprintf(stderr, "error: %s\n", (char *)data);
        break;

    case HTTP_CLIENT_EVENT_CONN_ESTABLISHED:
        for (size_t i = 0; i < c_ptr_vector_length(httpex.uris); i++) {
            struct http_uri *uri;

            uri = c_ptr_vector_entry(httpex.uris, i);

            http_client_request_empty(client, HTTP_GET, http_uri_clone(uri),
                                      NULL, httpex_on_client_response, NULL);
        }
        break;

    case HTTP_CLIENT_EVENT_CONN_FAILED:
        httpex_die("connection failed");
        break;

    case HTTP_CLIENT_EVENT_CONN_CLOSED:
        httpex.do_exit = true;
        break;
    }
}

static void
httpex_on_client_response(struct http_client *client,
                          struct http_response *response, void *arg) {
    const struct http_request *request;
    enum http_method method;
    enum http_status status;
    char *uri_string;

    request = http_response_request(response);
    method = http_request_method(request);
    uri_string = http_uri_to_string(http_request_target_uri(request));

    status = http_response_status(response);
    printf("%s %s\n  %d %s\n",
           http_method_to_string(method), uri_string,
           status, http_status_to_string(status));

    c_free(uri_string);

    httpex.nb_responses++;
    if (httpex.nb_responses == c_ptr_vector_length(httpex.uris))
        http_client_disconnect(client);
}
