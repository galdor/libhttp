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

#ifndef LIBHTTP_INTERNAL_H
#define LIBHTTP_INTERNAL_H

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "http.h"

/* Time */
#define HTTP_RFC1123_DATE_BUFSZ 64

void http_format_date(char [static HTTP_RFC1123_DATE_BUFSZ], size_t,
                      const struct tm *);
int http_format_timestamp(char buf[static HTTP_RFC1123_DATE_BUFSZ], size_t,
                          time_t);

/* Strings */
void http_string_vector_delete(struct c_ptr_vector *);

/* Path */
struct http_path {
    struct c_ptr_vector *segments;
};

/* URI */
struct http_uri {
    char *scheme;
    char *user;
    char *password;
    char *host;
    char *port;
    uint16_t port_number;
    char *path;
    char *query;
    char *fragment;
};

/* Protocol */
#define HTTP_METHOD_MAX_LENGTH 7 /* OPTIONS */

int http_method_parse(const char *, size_t, enum http_method *);
const char *http_method_to_string(enum http_method);

#define HTTP_VERSION_MAX_LENGTH 8 /* HTTP/1.1 */

int http_version_parse(const char *, size_t, enum http_version *);
const char *http_version_to_string(enum http_version);

const char *http_status_to_string(enum http_status);

struct c_ptr_vector *http_list_parse(const char *);

/* Header */
#define HTTP_HEADER_NAME_MAX_LENGTH 256
#define HTTP_HEADER_VALUE_MAX_LENGTH 256

struct http_header {
    char *name;
    char *value;
};

struct http_headers {
    struct c_vector *headers;
};

/* Request */
#define HTTP_REQUEST_TARGET_MAX_LENGTH 2048
#define HTTP_REQUEST_MAX_CONTENT_LENGTH (64 * 1024 * 1024)

enum http_connection_option {
    HTTP_CONNECTION_KEEP_ALIVE = (1 << 0),
    HTTP_CONNECTION_CLOSE      = (1 << 1),
};

struct http_request {
    enum http_method method;
    enum http_version version;

    char *target;
    struct http_uri *target_uri;
    struct http_path *target_path;

    struct http_headers *headers;

    void *body;
    size_t body_sz;

    bool has_content_length;
    size_t content_length;

    uint32_t connection_options; /* enum http_connection_option */
};

struct http_request *http_request_new(void);
void http_request_delete(struct http_request *);

int http_request_parse(const char *, size_t, struct http_request **,
                       size_t *, enum http_status *);

void http_request_add_header(struct http_request *, const char *, const char *);
void http_request_add_header_nocopy(struct http_request *, char *, char *);

bool http_request_can_have_body(const struct http_request *);
bool http_request_close_connection(const struct http_request *);

/* Response */
struct http_response {
    struct http_request *request;

    enum http_version version;
    enum http_status status;

    struct http_headers *headers;

    void *body;
    size_t body_sz;
};

struct http_response *http_response_new(enum http_status);
void http_response_delete(struct http_response *);

void http_response_finalize(struct http_response *);
void http_response_to_buffer(const struct http_response *, struct c_buffer *);

void http_response_add_header(struct http_response *, const char *,
                              const char *);
void http_response_add_header_nocopy(struct http_response *, char *, char *);
void http_response_set_header(struct http_response *, const char *,
                              const char *);
void http_response_set_header_vprintf(struct http_response *, const char *,
                                      const char *, va_list);
void http_response_set_header_printf(struct http_response *, const char *,
                                     const char *, ...);

/* Router */
struct http_route {
    char *path_string;
    struct http_path *path;
    enum http_method method;

    http_route_cb cb;
    void *cb_arg;
};

struct http_route *http_route_new(void);
void http_route_delete(struct http_route *);

struct http_router {
    struct c_ptr_vector *routes;
};

const struct http_route *
http_router_find_route(const struct http_router *,
                       enum http_method, const struct http_path *,
                       enum http_status *);

/* Server */
struct http_server {
    struct io_base *io_base;
    struct io_tcp_server *tcp_server;

    struct http_router *router;

    http_server_event_cb event_cb;
    void *event_cb_arg;

    http_server_error_cb error_cb;
    void *error_cb_arg;
};

void http_server_signal_event(struct http_server *,
                              enum http_server_event, void *);
void http_server_trace(struct http_server *, const char *, ...)
    __attribute__ ((format(printf, 2, 3)));
void http_server_error(struct http_server *, const char *, ...)
    __attribute__ ((format(printf, 2, 3)));

/* Server connection */
struct http_server_conn {
    struct http_server *server;
    struct io_tcp_server_conn *tcp_conn;

    struct c_queue *requests;
    struct c_queue *responses;
};

struct http_server_conn *http_server_conn_new(struct http_server *,
                                              struct io_tcp_server_conn *);
void http_server_conn_delete(struct http_server_conn *);

void http_server_conn_disconnect(struct http_server_conn *);

int http_server_conn_write_response(struct http_server_conn *,
                                    const struct http_response *);
int http_server_conn_send_response(struct http_server_conn *,
                                   struct http_request *,
                                   struct http_response *);

#endif
