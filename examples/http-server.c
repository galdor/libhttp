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

#include <assert.h>
#include <inttypes.h>
#include <signal.h>
#include <string.h>

#include "../src/http.h"

struct httpex {
    struct io_base *base;
    struct http_server *server;
    struct http_router *router;
    bool do_exit;

    int timer;
};

static void httpex_die(const char *, ...)
    __attribute__ ((format(printf, 1, 2), noreturn));

static void httpex_on_signal(int, void *);

static void httpex_on_server_event(struct http_server *,
                                   enum http_server_event, void *,
                                   void *);

static void httpex_on_request_root_get(struct http_request *, void *);
static void httpex_on_request_number_get(struct http_request *, void *);
static void httpex_on_request_private_get(struct http_request *, void *);
static void httpex_on_request_delayed_get(struct http_request *, void *);
static void httpex_on_timer(int, uint64_t, void *);

static struct httpex httpex;

int
main(int argc, char **argv) {
    struct c_command_line *cmdline;
    const char *host, *port_string;
    uint16_t port;
    bool use_ssl;
    const char *cert_path, *key_path;

    httpex.timer = -1;

    cmdline = c_command_line_new();

    c_command_line_add_flag(cmdline, "s", "ssl", "use ssl");
    c_command_line_add_option(cmdline, NULL, "cert", "the ssl certificate",
                              "path", NULL);
    c_command_line_add_option(cmdline, NULL, "key", "the ssl private key",
                              "path", NULL);

    c_command_line_add_argument(cmdline, "the host to bind to", "host");
    c_command_line_add_argument(cmdline, "the port to listen on", "port");

    if (c_command_line_parse(cmdline, argc, argv) == -1)
        httpex_die("%s", c_get_error());

    host = c_command_line_argument_value(cmdline, 0);

    port_string = c_command_line_argument_value(cmdline, 1);
    if (c_parse_u16(port_string, &port, NULL) == -1)
        httpex_die("invalid port number: %s", c_get_error());

    use_ssl = c_command_line_is_option_set(cmdline, "ssl");
    if (use_ssl) {
        cert_path = c_command_line_option_value(cmdline, "cert");
        key_path = c_command_line_option_value(cmdline, "key");
    }

    if (use_ssl)
        io_ssl_initialize();

    httpex.base = io_base_new();

    if (io_base_watch_signal(httpex.base, SIGINT, httpex_on_signal, NULL) == -1)
        httpex_die("cannot watch signal: %s", c_get_error());
    if (io_base_watch_signal(httpex.base, SIGTERM, httpex_on_signal, NULL) == -1)
        httpex_die("cannot watch signal: %s", c_get_error());

    httpex.router = http_router_new();

    http_router_bind(httpex.router, "/", HTTP_GET,
                     httpex_on_request_root_get, NULL);
    http_router_bind(httpex.router, "/number/:n", HTTP_GET,
                     httpex_on_request_number_get, NULL);
    http_router_bind(httpex.router, "/private", HTTP_GET,
                     httpex_on_request_private_get, NULL);
    http_router_bind(httpex.router, "/delayed/:n", HTTP_GET,
                     httpex_on_request_delayed_get, NULL);

    httpex.server = http_server_new(httpex.base, httpex.router);
    http_server_set_event_cb(httpex.server, httpex_on_server_event, NULL);

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

    if (http_server_listen(httpex.server, host, port) == -1)
        httpex_die("cannot listen: %s", c_get_error());

    while (!httpex.do_exit) {
        if (io_base_read_events(httpex.base) == -1)
            httpex_die("cannot read events: %s", c_get_error());
    }

    http_server_delete(httpex.server);
    http_router_delete(httpex.router);
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
        http_server_stop(httpex.server);
        httpex.do_exit = true;
        break;
    }
}

static void
httpex_on_server_event(struct http_server *server,
                       enum http_server_event event, void *data,
                       void *arg) {
    struct http_server_conn *conn;

    switch (event) {
    case HTTP_SERVER_EVENT_TRACE:
        printf("%s\n", (const char *)data);
        break;

    case HTTP_SERVER_EVENT_ERROR:
        fprintf(stderr, "error: %s\n", (char *)data);
        break;

    case HTTP_SERVER_EVENT_LISTENING:
        break;

    case HTTP_SERVER_EVENT_STOPPED:
        httpex.do_exit = true;
        break;

    case HTTP_SERVER_EVENT_CONN_ACCEPTED:
        conn = data;
        printf("%s  connection accepted\n",
               io_address_host_string(http_server_conn_address(conn)));
        break;

    case HTTP_SERVER_EVENT_CONN_CLOSED:
        conn = data;
        printf("%s  connection closed\n",
               io_address_host_string(http_server_conn_address(conn)));
        break;
    }
}

static void
httpex_on_request_root_get(struct http_request *request, void *arg) {
    http_reply_string(request, HTTP_200_OK, NULL, "hello world\n");
}

static void
httpex_on_request_number_get(struct http_request *request, void *arg) {
    const char *string;
    int64_t number;
    char *body;
    int body_sz;

    string = http_request_named_parameter(request, "n");
    if (!string) {
        http_reply_error(request, HTTP_406_NOT_ACCEPTABLE, NULL, NULL, NULL);
        return;
    }

    if (c_parse_i64(string, &number, NULL) == -1) {
        http_reply_error(request, HTTP_406_NOT_ACCEPTABLE, NULL, NULL,
                         "cannot parse number: %s", c_get_error());
        return;
    }

    body_sz = c_asprintf(&body, "%"PRIi64"\n", number);

    http_reply_data_nocopy(request, HTTP_200_OK, NULL, body, (size_t)body_sz);
}

static void
httpex_on_request_private_get(struct http_request *request, void *arg) {
    const char *user, *password;

    if (!http_request_has_auth_data(request)
     || http_request_auth_scheme(request) != HTTP_AUTH_SCHEME_BASIC) {
        struct http_headers *headers;

        headers = http_headers_new();
        http_headers_set(headers, "WWW-Authenticate", "Basic realm=\"libhttp\"");

        http_reply_error(request, HTTP_401_UNAUTHORIZED, headers, NULL,
                         "missing authentication data");
        return;
    }

    http_request_basic_auth_data(request, &user, &password);

    if (strcmp(user, "root") != 0 || strcmp(password, "root") != 0) {
        http_reply_error(request, HTTP_401_UNAUTHORIZED, NULL, NULL,
                         "invalid credentials");
        return;
    }

    http_reply_string(request, HTTP_200_OK, NULL, "access authorized");
}

static void
httpex_on_request_delayed_get(struct http_request *request, void *arg) {
    const char *string;
    uint64_t delay;

    string = http_request_named_parameter(request, "n");
    if (!string) {
        http_reply_error(request, HTTP_406_NOT_ACCEPTABLE, NULL, NULL, NULL);
        return;
    }

    if (c_parse_u64(string, &delay, NULL) == -1) {
        http_reply_error(request, HTTP_406_NOT_ACCEPTABLE, NULL, NULL,
                         "cannot parse delay: %s", c_get_error());
        return;
    }

    assert(httpex.timer == -1);
    httpex.timer = io_base_add_timer(httpex.base, delay * 1000U, 0,
                                     httpex_on_timer, request);
    if (httpex.timer == -1) {
        http_reply_error(request, HTTP_500_INTERNAL_SERVER_ERROR, NULL, NULL,
                         "cannot create timer: %s", c_get_error());
        return;
    }
}

static void
httpex_on_timer(int timer, uint64_t delay, void *arg) {
    struct http_request *request;

    request = arg;

    http_reply_empty(request, HTTP_200_OK, NULL);

    io_base_remove_timer(httpex.base, httpex.timer);
    httpex.timer = -1;
}
