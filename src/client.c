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

static void http_client_on_tcp_event(struct io_tcp_client *,
                                     enum io_tcp_client_event, void *);
static void http_client_on_data(struct http_client *, bool);
static void http_client_on_response(struct http_client *,
                                    struct http_response *);

struct http_client *
http_client_new(struct io_base *io_base) {
    struct http_client *client;

    client = c_malloc0(sizeof(struct http_client));

    client->io_base = io_base;

    client->tcp_client = io_tcp_client_new(io_base,
                                           http_client_on_tcp_event, client);

    client->requests = c_queue_new();

    return client;
}

void
http_client_delete(struct http_client *client) {
    if (!client)
        return;

    io_tcp_client_delete(client->tcp_client);

    while (!c_queue_is_empty(client->requests)) {
        struct http_request *request;

        request = c_queue_pop(client->requests);
        http_request_delete(request);
    }
    c_queue_delete(client->requests);

    c_free0(client, sizeof(struct http_client));
}

const char *
http_client_host(const struct http_client *client) {
    return io_tcp_client_host(client->tcp_client);
}

uint16_t
http_client_port(const struct http_client *client) {
    return io_tcp_client_port(client->tcp_client);
}

void
http_client_set_event_cb(struct http_client *client,
                         http_client_event_cb cb, void *cb_arg) {
    client->event_cb = cb;
    client->event_cb_arg = cb_arg;
}

int
http_client_enable_ssl(struct http_client *client,
                       const struct io_ssl_client_cfg *cfg) {
    return io_tcp_client_enable_ssl(client->tcp_client, cfg);
}

int
http_client_connect(struct http_client *client,
                    const char *host, uint16_t port) {
    return io_tcp_client_connect(client->tcp_client, host, port);
}

int
http_client_connect_url(struct http_client *client,
                        const struct http_url *url,
                        const struct io_ssl_client_cfg *ssl_cfg) {
    const char *host;
    uint16_t port;

    host = url->host;

    port = url->port_number;
    if (port == 0) {
        const char *scheme;

        scheme = http_url_scheme(url);
        if (strcasecmp(scheme, "http") == 0) {
            port = 80;
        } else if (strcasecmp(scheme, "https") == 0) {
            if (!io_tcp_client_is_ssl_enabled(client->tcp_client)) {
                if (!ssl_cfg) {
                    c_set_error("missing ssl configuration for "
                                "https url scheme");
                    return -1;
                }

                if (http_client_enable_ssl(client, ssl_cfg) == -1) {
                    c_set_error("cannot enable ssl: %s", c_get_error());
                    return -1;
                }
            }

            port = 443;
        } else {
            c_set_error("unknown url scheme");
            return -1;
        }
    }

    if (http_client_connect(client, host, port) == -1) {
        c_set_error("cannot connect to %s:%u: %s", host, port, c_get_error());
        return -1;
    }

    return 0;
}

void
http_client_close(struct http_client *client) {
    io_tcp_client_close(client->tcp_client);
}

void
http_client_disconnect(struct http_client *client) {
    io_tcp_client_disconnect(client->tcp_client);
}

bool
http_client_is_connected(struct http_client *client) {
    return io_tcp_client_is_connected(client->tcp_client);
}

void
http_client_signal_event(struct http_client *client,
                         enum http_client_event event, void *arg) {
    if (!client->event_cb)
        return;

    client->event_cb(client, event, arg, client->event_cb_arg);
}

void
http_client_trace(struct http_client *client, const char *fmt, ...) {
    char buf[C_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, C_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    http_client_signal_event(client, HTTP_CLIENT_EVENT_TRACE, buf);
}

void
http_client_error(struct http_client *client, const char *fmt, ...) {
    char buf[C_ERROR_BUFSZ];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, C_ERROR_BUFSZ, fmt, ap);
    va_end(ap);

    http_client_signal_event(client, HTTP_CLIENT_EVENT_ERROR, buf);
}

void
http_client_write_request(struct http_client *client,
                          const struct http_request *request) {

    struct c_buffer *wbuf;

    wbuf = io_tcp_client_wbuf(client->tcp_client);
    http_request_to_buffer(request, wbuf);

    io_tcp_client_signal_data_written(client->tcp_client);
}

void
http_client_finalize_and_send_request(struct http_client *client,
                                      struct http_request *request,
                                      http_client_response_cb cb, void *arg) {
    http_request_finalize(request, client);
    http_client_send_request(client, request, cb, arg);
}

void
http_client_send_request(struct http_client *client,
                         struct http_request *request,
                         http_client_response_cb cb, void *cb_arg) {
    assert(!request->response_cb);

    request->response_cb = cb;
    request->response_cb_arg = cb_arg;

    http_client_write_request(client, request);

    c_queue_push(client->requests, request);
}

void
http_client_request_empty(struct http_client *client, enum http_method method,
                          struct http_url *url, struct http_headers *headers,
                          http_client_response_cb cb, void *cb_arg) {
    struct http_request *request;

    request = http_request_new();

    request->method = method;
    request->target_url = url;

    if (headers) {
        http_headers_merge_nocopy(request->headers, headers);
        http_headers_delete(headers);
    }

    http_client_finalize_and_send_request(client, request, cb, cb_arg);
}

void
http_client_request_data(struct http_client *client, enum http_method method,
                         struct http_url *url, struct http_headers *headers,
                         const void *data, size_t sz,
                         http_client_response_cb cb, void *cb_arg) {
    http_client_request_data_nocopy(client, method, url, headers,
                                    c_memdup(data, sz), sz, cb, cb_arg);
}

void
http_client_request_data_nocopy(struct http_client *client,
                                enum http_method method, struct http_url *url,
                                struct http_headers *headers,
                                void *data, size_t sz,
                                http_client_response_cb cb, void *cb_arg) {
    struct http_request *request;

    request = http_request_new();
    request->method = method;
    request->target_url = url;

    if (headers) {
        http_headers_merge_nocopy(request->headers, headers);
        http_headers_delete(headers);
    }

    request->body = data;
    request->body_sz = sz;

    http_client_finalize_and_send_request(client, request, cb, cb_arg);
}

void
http_client_request_string(struct http_client *client, enum http_method method,
                           struct http_url *url, struct http_headers *headers,
                           const char *string,
                           http_client_response_cb cb, void *cb_arg) {
    http_client_request_data(client, method, url, headers,
                             string, strlen(string), cb, cb_arg);
}

static void
http_client_on_tcp_event(struct io_tcp_client *tcp_client,
                         enum io_tcp_client_event event, void *arg) {
    struct http_client *client;

    client = arg;

    switch (event) {
    case IO_TCP_CLIENT_EVENT_CONN_ESTABLISHED:
        http_client_signal_event(client, HTTP_CLIENT_EVENT_CONN_ESTABLISHED,
                                 NULL);
        break;

    case IO_TCP_CLIENT_EVENT_CONN_FAILED:
        http_client_signal_event(client, HTTP_CLIENT_EVENT_CONN_FAILED, NULL);
        break;

    case IO_TCP_CLIENT_EVENT_CONN_CLOSED:
        http_client_on_data(client, true);
        http_client_signal_event(client, HTTP_CLIENT_EVENT_CONN_CLOSED, NULL);
        break;

    case IO_TCP_CLIENT_EVENT_ERROR:
        http_client_error(client, "%s", c_get_error());
        break;

    case IO_TCP_CLIENT_EVENT_DATA_READ:
        http_client_on_data(client, false);
        break;
    }
}

static void
http_client_on_data(struct http_client *client, bool connection_closed) {
    struct c_buffer *rbuf;

    rbuf = io_tcp_client_rbuf(client->tcp_client);

    while (c_buffer_length(rbuf) > 0) {
        struct http_response *response;
        uint32_t flags;
        size_t sz;
        int ret;

        flags = 0;
        if (connection_closed)
            flags |= HTTP_RESPONSE_PARSE_CONNECTION_CLOSED;

        ret = http_response_parse(c_buffer_data(rbuf), c_buffer_length(rbuf),
                                  flags, &response, &sz);
        if (ret == -1) {
            http_client_error(client, "cannot parse response: %s",
                              c_get_error());
            http_client_disconnect(client);
            return;
        } else if (ret == 0) {
            return;
        }

        c_buffer_skip(rbuf, sz);

        http_client_on_response(client, response);
    }
}

static void
http_client_on_response(struct http_client *client,
                        struct http_response *response) {
    struct http_request *request;

#if 0
    http_client_trace(client, "response");
    http_client_trace(client, "  version: %s",
                      http_version_to_string(response->version));
    http_client_trace(client, "  status: %d", response->status);
    http_client_trace(client, "  reason: %s", response->reason);
    http_client_trace(client, "  headers:");
    for (size_t i = 0; i < http_headers_nb_headers(response->headers); i++) {
        const char *name, *value;

        name = http_headers_nth_header(response->headers, i, &value);
        http_client_trace(client, "    '%s' -> '%s'", name, value);
    }
    http_client_trace(client, "body: %zu bytes", response->body_sz);
#endif

    request = c_queue_pop(client->requests);
    if (!request) {
        http_client_error(client, "response received without request");

        http_response_delete(response);
        http_client_disconnect(client);
        return;
    }

    response->request = request;

    if (request->response_cb)
        request->response_cb(client, response, request->response_cb_arg);

    http_request_delete(request);
    http_response_delete(response);
}
