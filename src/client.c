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
static void http_client_on_data(struct http_client *);
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

void
http_client_set_event_cb(struct http_client *client,
                         http_client_event_cb cb, void *cb_arg) {
    client->event_cb = cb;
    client->event_cb_arg = cb_arg;
}

int
http_client_connect(struct http_client *client,
                    const char *host, uint16_t port) {
    return io_tcp_client_connect(client->tcp_client, host, port);
}

void
http_client_disconnect(struct http_client *client) {
    io_tcp_client_disconnect(client->tcp_client);
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

static void
http_client_on_tcp_event(struct io_tcp_client *tcp_client,
                         enum io_tcp_client_event event, void *arg) {
    struct http_client *client;

    client = arg;

    switch (event) {
    case IO_TCP_CLIENT_EVENT_CONN_ESTABLISHED:
        http_client_signal_event(client, HTTP_CLIENT_EVENT_CONN_ESTABLISHED,
                                 NULL);

        /* XXX debug */
        const char *data = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
        io_tcp_client_write(client->tcp_client, data, strlen(data));
        break;

    case IO_TCP_CLIENT_EVENT_CONN_FAILED:
        http_client_signal_event(client, HTTP_CLIENT_EVENT_CONN_FAILED, NULL);
        break;

    case IO_TCP_CLIENT_EVENT_CONN_CLOSED:
        http_client_signal_event(client, HTTP_CLIENT_EVENT_CONN_CLOSED, NULL);
        break;

    case IO_TCP_CLIENT_EVENT_CONN_LOST:
        http_client_signal_event(client, HTTP_CLIENT_EVENT_CONN_LOST, NULL);
        break;

    case IO_TCP_CLIENT_EVENT_ERROR:
        http_client_error(client, "%s", c_get_error());
        break;

    case IO_TCP_CLIENT_EVENT_DATA_READ:
        http_client_on_data(client);
        break;
    }
}

static void
http_client_on_data(struct http_client *client) {
    struct c_buffer *rbuf;

    rbuf = io_tcp_client_rbuf(client->tcp_client);

    while (c_buffer_length(rbuf) > 0) {
        struct http_response *response;
        size_t sz;
        int ret;

        ret = http_response_parse(c_buffer_data(rbuf), c_buffer_length(rbuf),
                                  &response, &sz);
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

    /* XXX debug */
#if 1
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

    /* TODO callback */

    http_request_delete(request);
    http_response_delete(response);
}
