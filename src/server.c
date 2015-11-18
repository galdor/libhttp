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

    conn->disabled_keepalive = false;

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

const struct io_address *
http_server_conn_address(const struct http_server_conn *conn) {
    return io_tcp_server_conn_address(conn->tcp_conn);
}

void
http_server_conn_set_private_data(struct http_server_conn *conn, void *data) {
    conn->private_data = data;
}

void *
http_server_conn_private_data(const struct http_server_conn *conn) {
    return conn->private_data;
}

void
http_server_conn_disable_keepalive(struct http_server_conn *conn) {
    conn->disabled_keepalive = true;
}

void
http_server_conn_disconnect(struct http_server_conn *conn) {
    io_tcp_server_conn_disconnect(conn->tcp_conn);
}

void
http_server_conn_write_response(struct http_server_conn *conn,
                                const struct http_response *response) {
    struct c_buffer *wbuf;

    wbuf = io_tcp_server_conn_wbuf(conn->tcp_conn);
    http_response_to_buffer(response, wbuf);

    io_tcp_server_conn_signal_data_written(conn->tcp_conn);
}

void
http_server_conn_send_response(struct http_server_conn *conn,
                               struct http_request *request,
                               struct http_response *response) {
    struct http_server *server;
    assert(request->conn == conn);
    assert(!response->request);

    server = conn->server;

    response->request = request;
    http_response_finalize(response);

    if (conn->disabled_keepalive)
        http_response_set_header(response, "Connection", "close");

    if (server->response_cb && !request->dummy)
        server->response_cb(response, server->response_cb_arg);

    c_queue_push(conn->responses, response);

    if (request != c_queue_peek(conn->requests))
        return;

    do {
        struct http_response *qresponse;
        struct http_request *qrequest;
        bool close_required;

        qrequest = c_queue_peek(conn->requests);

        qresponse = c_queue_peek(conn->responses);
        if (qresponse->request != qrequest)
            break;

        http_server_conn_write_response(conn, qresponse);

        close_required = http_request_close_connection(qrequest);

        c_queue_pop(conn->requests);
        http_request_delete(request);

        c_queue_pop(conn->responses);
        http_response_delete(response);

        if (close_required || conn->disabled_keepalive) {
            http_server_conn_disconnect(conn);
            return;
        }
    } while (c_queue_length(conn->responses) > 0);
}

void
http_reply_verror(struct http_request *request, enum http_status status,
                  struct http_headers *headers, void *data,
                  const char *fmt, va_list ap) {
    struct http_server *server;
    char error[C_ERROR_BUFSZ];

    assert(request->conn);

    server = request->conn->server;
    assert(server->error_cb);

    if (fmt)
        vsnprintf(error, C_ERROR_BUFSZ, fmt, ap);

    server->error_cb(request, status, headers, data, fmt ? error : NULL,
                     server->error_cb_arg);
}

void
http_reply_error(struct http_request *request, enum http_status status,
                 struct http_headers *headers, void *data,
                 const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    http_reply_verror(request, status, headers, data, fmt, ap);
    va_end(ap);
}

void
http_reply_empty(struct http_request *request, enum http_status status,
                 struct http_headers *headers) {
    struct http_response *response;

    response = http_response_new();
    response->status = status;

    if (headers) {
        http_headers_merge_nocopy(response->headers, headers);
        http_headers_delete(headers);
    }

    http_server_conn_send_response(request->conn, request, response);
}

void
http_reply_data(struct http_request *request, enum http_status status,
                struct http_headers *headers, const void *data, size_t sz) {
    http_reply_data_nocopy(request, status, headers, c_memdup(data, sz), sz);
}

void
http_reply_data_nocopy(struct http_request *request, enum http_status status,
                       struct http_headers *headers, void *data, size_t sz) {
    struct http_response *response;

    response = http_response_new();
    response->status = status;

    if (headers) {
        http_headers_merge_nocopy(response->headers, headers);
        http_headers_delete(headers);
    }

    response->body_sz = sz;
    response->body = data;

    http_server_conn_send_response(request->conn, request, response);
}

void
http_reply_string(struct http_request *request, enum http_status status,
                  struct http_headers *headers, const char *string) {
    struct http_response *response;

    response = http_response_new();
    response->status = status;

    if (headers) {
        http_headers_merge_nocopy(response->headers, headers);
        http_headers_delete(headers);
    }

    response->body_sz = strlen(string);
    response->body = c_strndup(string, response->body_sz);

    http_server_conn_send_response(request->conn, request, response);
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
            struct http_request *request;

            http_server_error(server, "cannot parse request: %s (%d %s)",
                              c_get_error(), status,
                              http_status_to_string(status));

            /* XXX Ugly hack. There is no request, but the API is designed to
             * only pass a response (which references the connection). */

            request = http_request_new();
            request->conn = conn;
            request->dummy = true;
            c_queue_push(conn->requests, request);

            http_reply_error(request, status, NULL, NULL, "%s", c_get_error());
            http_server_conn_disconnect(conn);
            return;
        } else if (ret == 0) {
            return;
        }

        c_buffer_skip(rbuf, sz);

        http_server_conn_on_request(conn, request);
        if (conn->do_close) {
            http_server_conn_disconnect(conn);
            return;
        }
    }
}

static void
http_server_conn_on_request(struct http_server_conn *conn,
                            struct http_request *request) {
    const struct http_route *route;
    struct http_server *server;
    enum http_status status;

    server = conn->server;

    request->conn = conn;

    c_queue_push(conn->requests, request);

    route = http_router_find_route(conn->server->router,
                                   request->method, request->target_path,
                                   &status);
    if (route)
        http_request_extract_named_parameters(request, route);

    if (server->request_cb) {
        server->request_cb(request, server->request_cb_arg,
                           route ? route->cb_arg : NULL);
        if (conn->do_close)
            return;

        if (c_queue_peek(conn->requests) != request) {
            /* A response was sent in the callback (yes, this is a hack) */
            return;
        }
    }

    if (!route) {
        http_reply_error(request, status, NULL, NULL, NULL);
        return;
    }

    route->cb(request, route->cb_arg);
    if (conn->do_close)
        return;
}

/* ---------------------------------------------------------------------------
 *  Server
 * ------------------------------------------------------------------------ */
static void http_server_on_tcp_event(struct io_tcp_server *,
                                     struct io_tcp_server_conn *,
                                     enum io_tcp_server_event, void *);

static void http_server_default_error_cb(struct http_request *,
                                         enum http_status, struct http_headers *,
                                         void *, const char *, void *);

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
http_server_set_request_cb(struct http_server *server,
                         http_server_request_cb cb, void *cb_arg) {
    server->request_cb = cb;
    server->request_cb_arg = cb_arg;
}

void
http_server_set_response_cb(struct http_server *server,
                         http_server_response_cb cb, void *cb_arg) {
    server->response_cb = cb;
    server->response_cb_arg = cb_arg;
}

void
http_server_set_error_cb(struct http_server *server,
                         http_server_error_cb cb, void *cb_arg) {
    server->error_cb = cb;
    server->error_cb_arg = cb_arg;
}

int
http_server_enable_ssl(struct http_server *server,
                       const struct io_ssl_server_cfg *cfg) {
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

        conn = http_server_conn_new(server, tcp_conn);
        io_tcp_server_conn_set_private_data(tcp_conn, conn);

        http_server_signal_event(server, HTTP_SERVER_EVENT_CONN_ACCEPTED, conn);
        break;

    case IO_TCP_SERVER_EVENT_CONN_CLOSED:
        http_server_signal_event(server, HTTP_SERVER_EVENT_CONN_CLOSED, conn);

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

static void
http_server_default_error_cb(struct http_request *request,
                             enum http_status status,
                             struct http_headers *headers,
                             void *data, const char *error, void *arg) {
    char *body;
    int body_sz;

    if (!headers)
        headers = http_headers_new();
    http_headers_set(headers, "Content-Type", "text/html");

    body_sz = c_asprintf(&body, "<h1>%d %s</h1><p>%s</p>",
                         status, http_status_to_string(status), error);

    http_reply_data_nocopy(request, status, headers, body, (size_t)body_sz);
}
