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
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "http.h"

/* ---------------------------------------------------------------------------
 *  Time
 * ------------------------------------------------------------------------ */
#define HTTP_RFC1123_DATE_BUFSZ 64

void http_format_date(char [static HTTP_RFC1123_DATE_BUFSZ], size_t,
                      const struct tm *);
int http_format_timestamp(char buf[static HTTP_RFC1123_DATE_BUFSZ], size_t,
                          time_t);

/* ---------------------------------------------------------------------------
 *  Strings
 * ------------------------------------------------------------------------ */
void http_string_vector_delete(struct c_ptr_vector *);

/* ---------------------------------------------------------------------------
 *  Path
 * ------------------------------------------------------------------------ */
struct http_path {
    struct c_ptr_vector *segments;
};

/* ---------------------------------------------------------------------------
 *  Query parameter
 * ------------------------------------------------------------------------ */
struct http_query_parameter {
    char *name;
    char *value;
};

void http_query_parameter_init(struct http_query_parameter *);
void http_query_parameter_free(struct http_query_parameter *);

struct c_vector *http_query_parameters_parse(const char *);

/* ---------------------------------------------------------------------------
 *  URI
 * ------------------------------------------------------------------------ */
struct http_url {
    char *scheme;
    char *user;
    char *password;
    char *host;
    char *port;
    uint16_t port_number;
    char *path;
    char *query;
    char *fragment;

    struct c_vector *query_parameters;
};

/* ---------------------------------------------------------------------------
 *  MIME
 * ------------------------------------------------------------------------ */
struct http_media_type {
    char *string;
    char *base_string;

    char *type;    /* case insensitive */
    char *subtype; /* case insensitive */

    struct c_hash_table *parameters;
};

/* ---------------------------------------------------------------------------
 *  Protocol
 * ------------------------------------------------------------------------ */
#define HTTP_METHOD_MAX_LENGTH 7 /* OPTIONS */

#define HTTP_VERSION_MAX_LENGTH 8 /* HTTP/1.1 */

#define HTTP_REASON_MAX_LENGTH 256

struct c_ptr_vector *http_list_parse(const char *);

/* ---------------------------------------------------------------------------
 *  Authentication
 * ------------------------------------------------------------------------ */
struct http_auth {
    enum http_auth_scheme scheme;

    union {
        struct {
            char *user;
            char *password;
        } basic;
    } u;
};

struct http_auth *http_auth_new(void);
void http_auth_delete(struct http_auth *);

struct http_auth *http_auth_parse_authorization(const char *);

/* ---------------------------------------------------------------------------
 *  Header
 * ------------------------------------------------------------------------ */
#define HTTP_HEADER_NAME_MAX_LENGTH 256
#define HTTP_HEADER_VALUE_MAX_LENGTH 2048

struct http_header {
    char *name;
    char *value;
};

struct http_headers {
    struct c_vector *headers;
};

int http_headers_parse(const char *, size_t, struct http_headers **,
                       enum http_status *, size_t *);

/* ---------------------------------------------------------------------------
 *  Chunked data
 * ------------------------------------------------------------------------ */
int http_chunked_data_parse(const void *, size_t, void **, size_t *, size_t *);

/* ---------------------------------------------------------------------------
 *  Request
 * ------------------------------------------------------------------------ */
#define HTTP_REQUEST_TARGET_MAX_LENGTH 2048
#define HTTP_REQUEST_MAX_CONTENT_LENGTH (64 * 1024 * 1024)

struct http_route;

enum http_connection_option {
    HTTP_CONNECTION_KEEP_ALIVE = (1 << 0),
    HTTP_CONNECTION_CLOSE      = (1 << 1),
};

struct http_request {
    enum http_method method;
    enum http_version version;

    char *target;
    struct http_url *target_url;

    struct http_headers *headers;

    void *body;
    size_t body_sz;

    /* When the request was received and parsed */
    struct http_server_conn *conn;

    struct http_path *target_path;
    struct c_hash_table *named_parameters;

    bool has_content_length;
    size_t content_length;

    uint32_t connection_options; /* enum http_connection_option */

    struct http_auth *auth;

    bool dummy;

    /* When the request was generated and sent */
    http_client_response_cb response_cb;
    void *response_cb_arg;
};

struct http_request *http_request_new(void);

void http_request_extract_named_parameters(struct http_request *,
                                           const struct http_route *);
void http_request_finalize(struct http_request *, struct http_client *);

void http_request_to_buffer(const struct http_request *, struct c_buffer *);

bool http_request_can_have_body(const struct http_request *);
bool http_request_close_connection(const struct http_request *);

/* ---------------------------------------------------------------------------
 *  Response
 * ------------------------------------------------------------------------ */
#define HTTP_RESPONSE_MAX_CONTENT_LENGTH (64 * 1024 * 1024)

struct http_response {
    struct http_request *request;

    enum http_version version;
    enum http_status status;
    char *reason;

    struct http_headers *headers;

    void *body;
    size_t body_sz;

    /* When the response was parsed, not generated */
    bool has_content_length;
    size_t content_length;
    bool is_body_chunked;

    bool has_connection_close;
};

struct http_response *http_response_new(void);
void http_response_delete(struct http_response *);

enum http_response_parse_flag {
    HTTP_RESPONSE_PARSE_EOF = (1 << 0),
};

int http_response_parse(const char *, size_t, uint32_t,
                        struct http_response **, size_t *);

void http_response_finalize(struct http_response *);
void http_response_to_buffer(const struct http_response *, struct c_buffer *);

bool http_response_can_have_body(const struct http_response *);

/* ---------------------------------------------------------------------------
 *  Client
 * ------------------------------------------------------------------------ */
struct http_client {
    struct io_base *io_base;
    struct io_tcp_client *tcp_client;

    http_client_event_cb event_cb;
    void *event_cb_arg;

    struct c_queue *requests;
};

void http_client_signal_event(struct http_client *,
                              enum http_client_event, void *);
void http_client_trace(struct http_client *, const char *, ...)
    __attribute__ ((format(printf, 2, 3)));
void http_client_error(struct http_client *, const char *, ...)
    __attribute__ ((format(printf, 2, 3)));

void http_client_write_request(struct http_client *,
                               const struct http_request *);
void http_client_finalize_and_send_request(struct http_client *,
                                           struct http_request *,
                                           http_client_response_cb, void *);

/* ---------------------------------------------------------------------------
 *  Router
 * ------------------------------------------------------------------------ */
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

/* ---------------------------------------------------------------------------
 *  Server
 * ------------------------------------------------------------------------ */
struct http_server {
    struct io_base *io_base;
    struct io_tcp_server *tcp_server;

    struct http_router *router;

    http_server_event_cb event_cb;
    void *event_cb_arg;

    http_server_request_cb request_cb;
    void *request_cb_arg;

    http_server_response_cb response_cb;
    void *response_cb_arg;

    http_server_error_cb error_cb;
    void *error_cb_arg;
};

void http_server_signal_event(struct http_server *,
                              enum http_server_event, void *);
void http_server_trace(struct http_server *, const char *, ...)
    __attribute__ ((format(printf, 2, 3)));
void http_server_error(struct http_server *, const char *, ...)
    __attribute__ ((format(printf, 2, 3)));

/* ---------------------------------------------------------------------------
 *  Server connection
 * ------------------------------------------------------------------------ */
struct http_server_conn {
    struct http_server *server;
    struct io_tcp_server_conn *tcp_conn;

    struct c_queue *requests;
    struct c_queue *responses;

    void *private_data;

    bool disabled_keepalive;
    bool do_close;
};

struct http_server_conn *http_server_conn_new(struct http_server *,
                                              struct io_tcp_server_conn *);
void http_server_conn_delete(struct http_server_conn *);

void http_server_conn_write_response(struct http_server_conn *,
                                    const struct http_response *);
void http_server_conn_send_response(struct http_server_conn *,
                                    struct http_request *,
                                    struct http_response *);

#endif
