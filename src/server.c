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

#include "internal.h"

/* ---------------------------------------------------------------------------
 *  Server connection
 * ------------------------------------------------------------------------ */
static void http_server_conn_on_data(struct http_server_conn *);
static void http_server_conn_on_request(struct http_server_conn *,
                                        struct http_request *);

struct http_server_conn *
http_server_conn_new(struct http_server *server,
                     struct io_tcp_server_conn *tcp_conn) {
    struct http_server_conn *conn;

    conn = c_malloc0(sizeof(struct http_server_conn));

    conn->server = server;
    conn->tcp_conn = tcp_conn;

    conn->requests = c_queue_new();
    conn->responses = c_queue_new();

    return conn;
}

void
http_server_conn_delete(struct http_server_conn *conn) {
    if (!conn)
        return;

    while (!c_queue_is_empty(conn->requests)) {
        struct http_request *request;

        request = c_queue_pop(conn->requests);
        http_request_delete(request);
    }
    c_queue_delete(conn->requests);

    while (!c_queue_is_empty(conn->responses)) {
        struct http_response *response;

        response = c_queue_pop(conn->responses);
        http_response_delete(response);
    }
    c_queue_delete(conn->responses);

    c_free0(conn, sizeof(struct http_server_conn));
}

void
http_server_conn_disconnect(struct http_server_conn *conn) {
    io_tcp_server_conn_disconnect(conn->tcp_conn);
}

int
http_server_conn_write_response(struct http_server_conn *conn,
                                const struct http_response *response) {
    struct c_buffer *wbuf;

    wbuf = io_tcp_server_conn_wbuf(conn->tcp_conn);
    http_response_to_buffer(response, wbuf);

    return io_tcp_server_conn_signal_data_written(conn->tcp_conn);
}

int
http_server_conn_send_response(struct http_server_conn *conn,
                               struct http_request *request,
                               struct http_response *response) {
    assert(!response->request);

    response->request = request;

    http_response_finalize(response);

    if (!request) {
        if (http_server_conn_write_response(conn, response) == -1)
            goto error;

        http_response_delete(response);
        return 0;
    }

    if (request == c_queue_peek(conn->requests)) {
        if (http_server_conn_write_response(conn, response) == -1)
            goto error;

        c_queue_pop(conn->requests);
        http_request_delete(request);

        http_response_delete(response);

        while (c_queue_length(conn->responses) > 0) {
            struct http_response *oresponse;
            struct http_request *orequest;

            oresponse = c_queue_peek(conn->responses);
            orequest = c_queue_peek(conn->requests);

            if (oresponse->request != orequest)
                break;

            if (http_server_conn_write_response(conn, oresponse) == -1)
                goto error;

            c_queue_pop(conn->requests);
            http_request_delete(request);

            c_queue_pop(conn->responses);
            http_response_delete(response);
        }

        return 0;
    }

    c_queue_push(conn->responses, response);

    return 0;

error:
    http_response_delete(response);

    http_server_error(conn->server, "connection error: %s", c_get_error());
    http_server_conn_disconnect(conn);
    return -1;
}

int
http_server_conn_reply_error(struct http_server_conn *conn,
                             struct http_request *request,
                             enum http_status status,
                             struct http_headers *headers,
                             const char *fmt, ...) {
    struct http_server *server;
    char error[C_ERROR_BUFSZ];
    va_list ap;

    server = conn->server;
    assert(server->error_cb);

    if (fmt) {
        va_start(ap, fmt);
        vsnprintf(error, C_ERROR_BUFSZ, fmt, ap);
        va_end(ap);
    } else {
        c_strlcpy(error, http_status_to_string(status), C_ERROR_BUFSZ);
    }

    if (server->error_cb(conn, request, status, headers, error,
                         server->error_cb_arg) == -1) {
        return -1;
    }

    http_server_conn_disconnect(conn);
    return 0;
}

int
http_server_conn_reply_empty(struct http_server_conn *conn,
                             struct http_request *request,
                             enum http_status status,
                             struct http_headers *headers) {
    struct http_response *response;

    response = http_response_new();
    response->status = status;

    if (headers) {
        http_headers_merge_nocopy(response->headers, headers);
        http_headers_delete(headers);
    }

    return http_server_conn_send_response(conn, request, response);
}

int
http_server_conn_reply_data(struct http_server_conn *conn,
                            struct http_request *request,
                            enum http_status status,
                            struct http_headers *headers,
                            const void *data, size_t sz) {
    struct http_response *response;

    response = http_response_new();
    response->status = status;

    if (headers) {
        http_headers_merge_nocopy(response->headers, headers);
        http_headers_delete(headers);
    }

    response->body_sz = sz;
    response->body = c_memdup(data, sz);

    return http_server_conn_send_response(conn, request, response);
}

int
http_server_conn_reply_string(struct http_server_conn *conn,
                              struct http_request *request,
                              enum http_status status,
                              struct http_headers *headers,
                              const char *string) {
    struct http_response *response;

    response = http_response_new();
    response->status = status;

    if (headers) {
        http_headers_merge_nocopy(response->headers, headers);
        http_headers_delete(headers);
    }

    response->body_sz = strlen(string);
    response->body = c_strndup(string, response->body_sz);

    return http_server_conn_send_response(conn, request, response);
}

int
http_server_conn_reply_printf(struct http_server_conn *conn,
                              struct http_request *request,
                              enum http_status status,
                              struct http_headers *headers,
                              const char *fmt, ...) {
    va_list ap;
    char *body;
    int body_sz;

    va_start(ap, fmt);
    body_sz = c_vasprintf(&body, fmt, ap);
    va_end(ap);

    return http_server_conn_reply_data(conn, request, status, headers,
                                       body, (size_t)body_sz);
}

static void
http_server_conn_on_data(struct http_server_conn *conn) {
    struct http_server *server;
    struct c_buffer *rbuf;

    server = conn->server;
    rbuf = io_tcp_server_conn_rbuf(conn->tcp_conn);

    while (c_buffer_length(rbuf) > 0) {
        struct http_request *request;
        enum http_status status;
        size_t sz;
        int ret;

        ret = http_request_parse(c_buffer_data(rbuf), c_buffer_length(rbuf),
                                 &request, &sz, &status);
        if (ret == -1) {
            http_server_error(server, "cannot parse request: %s (%d %s)",
                              c_get_error(), status,
                              http_status_to_string(status));
            http_server_conn_reply_error(conn, NULL, status, NULL,
                                         "%s", c_get_error());
            return;
        } else if (ret == 0) {
            return;
        }

        c_buffer_skip(rbuf, sz);

        http_server_conn_on_request(conn, request);
    }
}

static void
http_server_conn_on_request(struct http_server_conn *conn,
                            struct http_request *request) {
    const struct http_route *route;
    enum http_status status;
    bool do_close;

    c_queue_push(conn->requests, request);

    do_close = http_request_close_connection(request);

    route = http_router_find_route(conn->server->router,
                                   request->method, request->target_path,
                                   &status);
    if (!route) {
        http_server_conn_reply_error(conn, request, status, NULL, NULL);
        return;
    }

    if (route->cb(conn, request, route->cb_arg) == -1) {
        http_server_error(conn->server, "connection error: %s", c_get_error());
        http_server_conn_disconnect(conn);
        return;
    }

    if (do_close) {
        http_server_conn_disconnect(conn);
        return;
    }
}

/* ---------------------------------------------------------------------------
 *  Server
 * ------------------------------------------------------------------------ */
static void http_server_on_tcp_event(struct io_tcp_server *,
                                     struct io_tcp_server_conn *,
                                     enum io_tcp_server_event, void *);

static int http_server_default_error_cb(struct http_server_conn *,
                                        struct http_request *,
                                        enum http_status,
                                        struct http_headers *,
                                        const char *, void *);

struct http_server *
http_server_new(struct io_base *io_base, struct http_router *router) {
    struct http_server *server;

    server = c_malloc0(sizeof(struct http_server));

    server->io_base = io_base;

    server->tcp_server = io_tcp_server_new(io_base,
                                           http_server_on_tcp_event, server);

    server->router = router;

    server->error_cb = http_server_default_error_cb;

    return server;
}

void
http_server_delete(struct http_server *server) {
    if (!server)
        return;

    io_tcp_server_delete(server->tcp_server);

    c_free0(server, sizeof(struct http_server));
}

const char *
http_server_host(const struct http_server *server) {
    return io_tcp_server_host(server->tcp_server);
}

uint16_t
http_server_port(const struct http_server *server) {
    return io_tcp_server_port(server->tcp_server);
}

size_t
http_server_nb_listening_addresses(const struct http_server *server) {
    return io_tcp_server_nb_listeners(server->tcp_server);
}

const struct io_address *
http_server_nth_listening_address(const struct http_server *server,
                                  size_t idx) {
    const struct io_tcp_listener *listener;

    listener = io_tcp_server_nth_listener(server->tcp_server, idx);
    return io_tcp_listener_address(listener);
}

void
http_server_set_event_cb(struct http_server *server,
                         http_server_event_cb cb, void *cb_arg) {
    server->event_cb = cb;
    server->event_cb_arg = cb_arg;
}

void
http_server_set_error_cb(struct http_server *server,
                         http_server_error_cb cb, void *cb_arg) {
    server->error_cb = cb;
    server->error_cb_arg = cb_arg;
}

int
http_server_enable_ssl(struct http_server *server,
                       const struct io_ssl_cfg *cfg) {
    return io_tcp_server_enable_ssl(server->tcp_server, cfg);
}

int
http_server_listen(struct http_server *server,
                   const char *host, uint16_t port) {
    return io_tcp_server_listen(server->tcp_server, host, port);
}

void
http_server_stop(struct http_server *server) {
    io_tcp_server_stop(server->tcp_server);
}

void
http_server_signal_event(struct http_server *server,
                         enum http_server_event event, void *arg) {
    if (!server->event_cb)
        return;

    server->event_cb(server, event, arg, server->event_cb_arg);
}

void
http_server_trace(struct http_server *server, const char *fmt, ...) {
    char buf[C_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, C_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    http_server_signal_event(server, HTTP_SERVER_EVENT_TRACE, buf);
}

void
http_server_error(struct http_server *server, const char *fmt, ...) {
    char buf[C_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, C_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    http_server_signal_event(server, HTTP_SERVER_EVENT_ERROR, buf);
}

static void
http_server_on_tcp_event(struct io_tcp_server *tcp_server,
                         struct io_tcp_server_conn *tcp_conn,
                         enum io_tcp_server_event event, void *arg) {
    struct http_server *server;
    struct http_server_conn *conn;
    const struct io_address *addr;

    server = arg;

    if (tcp_conn) {
        conn = io_tcp_server_conn_private_data(tcp_conn);
    } else {
        conn = NULL;
    }

    switch (event) {
    case IO_TCP_SERVER_EVENT_SERVER_LISTENING:
        http_server_signal_event(server, HTTP_SERVER_EVENT_LISTENING, NULL);
        break;

    case IO_TCP_SERVER_EVENT_SERVER_STOPPED:
        http_server_signal_event(server, HTTP_SERVER_EVENT_STOPPED, NULL);
        break;

    case IO_TCP_SERVER_EVENT_CONN_ACCEPTED:
        addr = io_tcp_server_conn_address(tcp_conn);
        http_server_trace(server, "connection from %s",
                          io_address_host_port_string(addr));

        conn = http_server_conn_new(server, tcp_conn);
        io_tcp_server_conn_set_private_data(tcp_conn, conn);
        break;

    case IO_TCP_SERVER_EVENT_CONN_CLOSED:
        http_server_conn_delete(conn);
        io_tcp_server_conn_set_private_data(tcp_conn, NULL);
        break;

    case IO_TCP_SERVER_EVENT_CONN_LOST:
        http_server_conn_delete(conn);
        io_tcp_server_conn_set_private_data(tcp_conn, NULL);
        break;

    case IO_TCP_SERVER_EVENT_ERROR:
        http_server_error(server, "%s", c_get_error());
        break;

    case IO_TCP_SERVER_EVENT_DATA_READ:
        http_server_conn_on_data(conn);
        break;
    }
}

static int
http_server_default_error_cb(struct http_server_conn *conn,
                             struct http_request *request,
                             enum http_status status,
                             struct http_headers *headers,
                             const char *error, void *arg) {
    char *body;
    int body_sz;

    if (!headers)
        headers = http_headers_new();
    http_headers_set(headers, "Content-Type", "text/html");

    body_sz = c_asprintf(&body, "<h1>%d %s</h1><p>%s</p>",
                         status, http_status_to_string(status), error);

    if (http_server_conn_reply_data(conn, request, status, headers,
                                    body, (size_t)body_sz) == -1) {
        c_free(body);
        return -1;
    }

    return 0;
}
