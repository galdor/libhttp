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

#ifndef LIBHTTP_HTTP_H
#define LIBHTTP_HTTP_H

#include <core.h>
#include <io.h>

/* ---------------------------------------------------------------------------
 *  Base64
 * ------------------------------------------------------------------------ */
uint8_t *http_base64_decode(const void *, size_t, size_t *);
uint8_t *http_base64_encode(const void *, size_t, size_t *);

char *http_base64_decode_string(const char *);
char *http_base64_encode_string(const char *);

/* ---------------------------------------------------------------------------
 *  Path
 * ------------------------------------------------------------------------ */
struct http_path *http_path_new(void);
void http_path_delete(struct http_path *);

struct http_path *http_path_parse(const char *);

size_t http_path_nb_segments(const struct http_path *);
const char *http_path_segment(const struct http_path *, size_t);

void http_path_add_segment(struct http_path *, const char *);
void http_path_add_segment2(struct http_path *, const char *, size_t);

/* ---------------------------------------------------------------------------
 *  URL
 * ------------------------------------------------------------------------ */
struct http_url *http_url_new(void);
void http_url_delete(struct http_url *);

struct http_url *http_url_parse(const char *);
void http_url_to_buffer(const struct http_url *, struct c_buffer *);
char *http_url_to_string(const struct http_url *);

struct http_url *http_url_clone(const struct http_url *);

const char *http_url_scheme(const struct http_url *);
const char *http_url_user(const struct http_url *);
const char *http_url_password(const struct http_url *);
const char *http_url_host(const struct http_url *);
const char *http_url_port(const struct http_url *);
uint16_t http_url_port_number(const struct http_url *);
const char *http_url_path(const struct http_url *);
const char *http_url_query(const struct http_url *);
const char *http_url_fragment(const struct http_url *);

void http_url_set_scheme(struct http_url *, const char *);
void http_url_set_user(struct http_url *, const char *);
void http_url_set_password(struct http_url *, const char *);
void http_url_set_host(struct http_url *, const char *);
void http_url_set_port(struct http_url *, uint16_t);
void http_url_set_path(struct http_url *, const char *);
void http_url_set_query(struct http_url *, const char *);
void http_url_set_fragment(struct http_url *, const char *);

size_t http_url_nb_query_parameters(const struct http_url *);
const char *http_url_nth_query_parameter(const struct http_url *, size_t,
                                         const char **);
bool http_url_has_query_parameter(const struct http_url *, const char *,
                                  const char **);
const char *http_url_query_parameter(const struct http_url *, const char *);

bool http_url_equal(const struct http_url *, const struct http_url *);

/* ---------------------------------------------------------------------------
 *  MIME
 * ------------------------------------------------------------------------ */
struct http_media_type *http_media_type_new(const char *, const char *);
void http_media_type_delete(struct http_media_type *);

struct http_media_type *http_media_type_parse(const char *);

const char *http_media_type_string(const struct http_media_type *);
const char *http_media_type_base_string(const struct http_media_type *);
const char *http_media_type_type(const struct http_media_type *);
const char *http_media_type_subtype(const struct http_media_type *);

const char *http_media_type_parameter(const struct http_media_type *,
                                      const char *);
void http_media_type_set_parameter(struct http_media_type *,
                                   const char *, const char *);
void
http_media_type_set_parameter_nocopy(struct http_media_type *,
                                     const char *, char *);

/* ---------------------------------------------------------------------------
 *  Protocol
 * ------------------------------------------------------------------------ */
/* Version */
enum http_version {
    HTTP_1_0,
    HTTP_1_1,
};

const char *http_version_to_string(enum http_version);
int http_version_parse(const char *, size_t, enum http_version *);

/* Method */
enum http_method {
    HTTP_GET,
    HTTP_HEAD,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_CONNECT,
    HTTP_OPTIONS,
    HTTP_TRACE,
};

const char *http_method_to_string(enum http_method);
int http_method_parse(const char *, size_t, enum http_method *);

/* Status */
enum http_status {
    /* 1xx */
    HTTP_100_CONTINUE                        = 100,
    HTTP_101_SWITCHING_PROTOCOLS             = 101,

    /* 2xx */
    HTTP_200_OK                              = 200,
    HTTP_201_CREATED                         = 201,
    HTTP_202_ACCEPTED                        = 202,
    HTTP_203_NON_AUTHORITATIVE_INFORMATION   = 203,
    HTTP_204_NO_CONTENT                      = 204,
    HTTP_205_RESET_CONTENT                   = 205,
    HTTP_206_PARTIAL_CONTENT                 = 206,

    /* 3xx */
    HTTP_300_MULTIPLE_CHOICES                = 300,
    HTTP_301_MOVED_PERMANENTLY               = 301,
    HTTP_302_FOUND                           = 302,
    HTTP_303_SEE_OTHER                       = 303,
    HTTP_304_NOT_MODIFIED                    = 304,
    HTTP_305_USE_PROXY                       = 305,

    HTTP_307_TEMPORARY_REDIRECT              = 307,

    /* 4xx */
    HTTP_400_BAD_REQUEST                     = 400,
    HTTP_401_UNAUTHORIZED                    = 401,
    HTTP_402_PAYMENT_REQUIRED                = 402,
    HTTP_403_FORBIDDEN                       = 403,
    HTTP_404_NOT_FOUND                       = 404,
    HTTP_405_METHOD_NOT_ALLOWED              = 405,
    HTTP_406_NOT_ACCEPTABLE                  = 406,
    HTTP_407_PROXY_AUTHENTICATION_REQUIRED   = 407,
    HTTP_408_REQUEST_TIMEOUT                 = 408,
    HTTP_409_CONFLICT                        = 409,
    HTTP_410_GONE                            = 410,
    HTTP_411_LENGTH_REQUIRED                 = 411,
    HTTP_412_PRECONDITION_FAILED             = 412,
    HTTP_413_PAYLOAD_TOO_LARGE               = 413,
    HTTP_414_URI_TOO_LONG                    = 414,
    HTTP_415_UNSUPPORTED_MEDIA_TYPE          = 415,
    HTTP_416_RANGE_NOT_SATISFIABLE           = 416,
    HTTP_417_EXPECTATION_FAILED              = 417,

    HTTP_426_UPGRADE_REQUIRED                = 426,

    HTTP_428_PRECONDITION_REQUIRED           = 428,
    HTTP_429_TOO_MANY_REQUESTS               = 429,

    HTTP_431_REQUEST_HEADER_FIELDS_TOO_LARGE = 431,

    /* 5xx */
    HTTP_500_INTERNAL_SERVER_ERROR           = 500,
    HTTP_501_NOT_IMPLEMENTED                 = 501,
    HTTP_502_BAD_GATEWAY                     = 502,
    HTTP_503_SERVICE_UNAVAILABLE             = 503,
    HTTP_504_GATEWAY_TIMEOUT                 = 504,
    HTTP_505_HTTP_VERSION_NOT_SUPPORTED      = 505,

    HTTP_511_NETWORK_AUTHENTICATION_REQUIRED = 511,
};

const char *http_status_to_string(enum http_status);

bool http_status_is_success(enum http_status);

/* Content coding */
enum http_content_coding {
    HTTP_CONTENT_CODING_GZIP,
};

const char *http_content_coding_to_string(enum http_content_coding);
int http_content_coding_parse(const char *, enum http_content_coding *);

/* ---------------------------------------------------------------------------
 *  Authentication
 * ------------------------------------------------------------------------ */
enum http_auth_scheme {
    HTTP_AUTH_SCHEME_BASIC,
};

char *http_generate_basic_auth_header(const char *, const char *);

/* ---------------------------------------------------------------------------
 *  Headers
 * ------------------------------------------------------------------------ */
struct http_headers *http_headers_new(void);
void http_headers_delete(struct http_headers *);

struct http_headers *http_headers_clone(const struct http_headers *);

size_t http_headers_nb_headers(struct http_headers *);
const char *http_headers_nth_header(struct http_headers *, size_t, const char **);
const char *http_headers_header(struct http_headers *, const char *);
bool http_headers_has_header(struct http_headers *, const char *);

void http_headers_add(struct http_headers *, const char *, const char *);
void http_headers_add_nocopy(struct http_headers *, const char *, char *);
void http_headers_set(struct http_headers *, const char *, const char *);
void http_headers_set_nocopy(struct http_headers *, const char *, char *);
void http_headers_set_vprintf(struct http_headers *, const char *,
                              const char *, va_list);
void http_headers_set_printf(struct http_headers *, const char *,
                             const char *, ...)
    __attribute__ ((format(printf, 3, 4)));

void http_headers_merge_nocopy(struct http_headers *, struct http_headers *);

/* ---------------------------------------------------------------------------
 *  Request
 * ------------------------------------------------------------------------ */
struct http_request;

void http_request_delete(struct http_request *);

int http_request_parse(const char *, size_t, struct http_request **,
                       size_t *, enum http_status *);

enum http_method http_request_method(const struct http_request *);

struct http_url *http_request_target_url(const struct http_request *);
void http_request_set_target_url(struct http_request *,
                                 const struct http_url *);

struct http_server_conn *http_request_server_conn(const struct http_request *);

struct http_headers *http_request_headers(const struct http_request *);
size_t http_request_nb_headers(const struct http_request *);
bool http_request_has_header(const struct http_request *, const char *);
const char *http_request_nth_header(const struct http_request *, size_t,
                                    const char **);
const char *http_request_header(const struct http_request *, const char *);

void http_request_set_headers_nocopy(struct http_request *,
                                     struct http_headers *);
void http_request_set_headers(struct http_request *,
                              const struct http_headers *);
void http_request_add_header(struct http_request *, const char *, const char *);
void http_request_add_header_nocopy(struct http_request *,
                                    const char *, char *);
void http_request_set_header(struct http_request *, const char *,
                             const char *);
void http_request_set_header_vprintf(struct http_request *, const char *,
                                     const char *, va_list);
void http_request_set_header_printf(struct http_request *, const char *,
                                    const char *, ...)
    __attribute__ ((format(printf, 3, 4)));

size_t http_request_body_size(const struct http_request *);
void *http_request_body(const struct http_request *, size_t *);

const char *http_request_named_parameter(const struct http_request *,
                                         const char *);

bool http_request_has_auth_data(const struct http_request *);
enum http_auth_scheme http_request_auth_scheme(const struct http_request *);
void http_request_basic_auth_data(const struct http_request *,
                                  const char **, const char **);

size_t http_request_nb_query_parameters(const struct http_request *);
const char *http_request_nth_query_parameter(const struct http_request *,
                                             size_t, const char **);
bool http_request_has_query_parameter(const struct http_request *,
                                      const char *, const char **);
const char *http_request_query_parameter(const struct http_request *,
                                         const char *);

struct c_ptr_vector *
http_request_accepted_media_types(const struct http_request *);
int http_request_accepts_media_type(const struct http_request *,
                                    const char *, const char *);

/* ---------------------------------------------------------------------------
 *  Response
 * ------------------------------------------------------------------------ */
struct http_response;

struct http_request *http_response_request(const struct http_response *);
enum http_version http_response_version(const struct http_response *);
enum http_status http_response_status(const struct http_response *);
const char *http_response_reason(const struct http_response *);

size_t http_response_nb_headers(const struct http_response *);
bool http_response_has_header(const struct http_response *, const char *);
const char *http_response_nth_header(const struct http_response *, size_t,
                                     const char **);
const char *http_response_header(const struct http_response *, const char *);

void http_response_add_header(struct http_response *, const char *,
                              const char *);
void http_response_add_header_nocopy(struct http_response *,
                                     const char *, char *);
void http_response_set_header(struct http_response *, const char *,
                              const char *);
void http_response_set_header_vprintf(struct http_response *, const char *,
                                      const char *, va_list);
void http_response_set_header_printf(struct http_response *, const char *,
                                     const char *, ...)
    __attribute__ ((format(printf, 3, 4)));

void *http_response_body(const struct http_response *, size_t *);

struct http_url *
http_response_redirection_location(const struct http_response *);

/* ---------------------------------------------------------------------------
 *  Client
 * ------------------------------------------------------------------------ */
struct http_client;

enum http_client_event {
    HTTP_CLIENT_EVENT_TRACE,
    HTTP_CLIENT_EVENT_ERROR,
    HTTP_CLIENT_EVENT_CONN_ESTABLISHED,
    HTTP_CLIENT_EVENT_CONN_FAILED,
    HTTP_CLIENT_EVENT_CONN_CLOSED,
};

typedef void (*http_client_event_cb)(struct http_client *,
                                     enum http_client_event, void *,
                                     void *);
typedef void (*http_client_response_cb)(struct http_client *,
                                        struct http_response *, void *);

struct http_client *http_client_new(struct io_base *);
void http_client_delete(struct http_client *);

const char *http_client_host(const struct http_client *);
uint16_t http_client_port(const struct http_client *);

void http_client_set_event_cb(struct http_client *,
                              http_client_event_cb, void *);

int http_client_enable_ssl(struct http_client *,
                           const struct io_ssl_client_cfg *);
void http_client_toggle_gzip_decoding(struct http_client *, bool);

int http_client_connect(struct http_client *, const char *, uint16_t);
int http_client_connect_url(struct http_client *, const struct http_url *,
                            const struct io_ssl_client_cfg *);
void http_client_close(struct http_client *);
void http_client_disconnect(struct http_client *);
bool http_client_is_connected(struct http_client *);

void http_client_send_request(struct http_client *, struct http_request *,
                              http_client_response_cb, void *);
void http_client_request_empty(struct http_client *, enum http_method,
                               struct http_url *, struct http_headers *,
                               http_client_response_cb, void *);
void http_client_request_data(struct http_client *, enum http_method,
                              struct http_url *, struct http_headers *,
                              const void *, size_t,
                              http_client_response_cb, void *);
void http_client_request_data_nocopy(struct http_client *, enum http_method,
                                     struct http_url *, struct http_headers *,
                                     void *, size_t,
                                     http_client_response_cb, void *);
void http_client_request_string(struct http_client *, enum http_method,
                                struct http_url *, struct http_headers *,
                                const char *,
                                http_client_response_cb, void *);

/* ---------------------------------------------------------------------------
 *  Router
 * ------------------------------------------------------------------------ */
struct http_router;
struct http_server_conn;

typedef void (*http_route_cb)(struct http_request *, void *);

struct http_router *http_router_new(void);
void http_router_delete(struct http_router *);

int http_router_bind(struct http_router *, const char *, enum http_method,
                     http_route_cb, void *);

/* ---------------------------------------------------------------------------
 *  Server
 * ------------------------------------------------------------------------ */
struct http_server;

enum http_server_event {
    HTTP_SERVER_EVENT_TRACE,
    HTTP_SERVER_EVENT_ERROR,
    HTTP_SERVER_EVENT_LISTENING,
    HTTP_SERVER_EVENT_STOPPED,
    HTTP_SERVER_EVENT_CONN_ACCEPTED,
    HTTP_SERVER_EVENT_CONN_CLOSED,
};

typedef void (*http_server_event_cb)(struct http_server *,
                                     enum http_server_event, void *,
                                     void *);
typedef void (*http_server_request_cb)(struct http_request *, void *, void *);
typedef void (*http_server_response_cb)(struct http_response *, void *);
typedef void (*http_server_error_cb)(struct http_request *,
                                     enum http_status, struct http_headers *,
                                     void *, const char *, void *);

struct http_server *http_server_new(struct io_base *, struct http_router *);
void http_server_delete(struct http_server *);

const char *http_server_host(const struct http_server *);
uint16_t http_server_port(const struct http_server *);

size_t http_server_nb_listening_addresses(const struct http_server *);
const struct io_address *
http_server_nth_listening_address(const struct http_server *, size_t);

void http_server_set_event_cb(struct http_server *,
                              http_server_event_cb, void *);
void http_server_set_request_cb(struct http_server *,
                                http_server_request_cb, void *);
void http_server_set_response_cb(struct http_server *,
                                 http_server_response_cb, void *);
void http_server_set_error_cb(struct http_server *,
                              http_server_error_cb, void *);

int http_server_enable_ssl(struct http_server *,
                           const struct io_ssl_server_cfg *);

int http_server_listen(struct http_server *, const char *, uint16_t);
void http_server_stop(struct http_server *);

/* ---------------------------------------------------------------------------
 *  Server connection
 * ------------------------------------------------------------------------ */
const struct io_address *
http_server_conn_address(const struct http_server_conn *);

void http_server_conn_set_private_data(struct http_server_conn *, void *);
void *http_server_conn_private_data(const struct http_server_conn *);

void http_server_conn_disable_keepalive(struct http_server_conn *);

void http_server_conn_disconnect(struct http_server_conn *);

void http_reply_verror(struct http_request *, enum http_status,
                       struct http_headers *, void *, const char *, va_list);
void http_reply_error(struct http_request *, enum http_status,
                      struct http_headers *, void *, const char *, ...)
    __attribute__ ((format(printf, 5, 6)));

void http_reply_empty(struct http_request *, enum http_status,
                      struct http_headers *);
void http_reply_data(struct http_request *, enum http_status,
                     struct http_headers *, const void *, size_t);
void http_reply_data_nocopy(struct http_request *, enum http_status,
                            struct http_headers *, void *, size_t);
void http_reply_string(struct http_request *, enum http_status,
                       struct http_headers *, const char *);

#endif
