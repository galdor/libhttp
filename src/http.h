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

/* URI */
struct http_uri *http_uri_new(void);
void http_uri_delete(struct http_uri *);

struct http_uri *http_uri_parse(const char *);

const char *http_uri_scheme(const struct http_uri *);
const char *http_uri_user(const struct http_uri *);
const char *http_uri_password(const struct http_uri *);
const char *http_uri_host(const struct http_uri *);
const char *http_uri_port(const struct http_uri *);
uint16_t http_uri_port_number(const struct http_uri *);
const char *http_uri_path(const struct http_uri *);
const char *http_uri_query(const struct http_uri *);
const char *http_uri_fragment(const struct http_uri *);

/* Protocol */
enum http_version {
    HTTP_1_0,
    HTTP_1_1,
};

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

enum http_status {
    /* 1xx */
    HTTP_100_CONTINUE                      = 100,
    HTTP_101_SWITCHING_PROTOCOLS           = 101,

    /* 2xx */
    HTTP_200_OK                            = 200,
    HTTP_201_CREATED                       = 201,
    HTTP_202_ACCEPTED                      = 202,
    HTTP_203_NON_AUTHORITATIVE_INFORMATION = 203,
    HTTP_204_NO_CONTENT                    = 204,
    HTTP_205_RESET_CONTENT                 = 205,
    HTTP_206_PARTIAL_CONTENT               = 206,

    /* 3xx */
    HTTP_300_MULTIPLE_CHOICES              = 300,
    HTTP_301_MOVED_PERMANENTLY             = 301,
    HTTP_302_FOUND                         = 302,
    HTTP_303_SEE_OTHER                     = 303,
    HTTP_304_NOT_MODIFIED                  = 304,
    HTTP_305_USE_PROXY                     = 305,

    HTTP_307_TEMPORARY_REDIRECT            = 307,

    /* 4xx */
    HTTP_400_BAD_REQUEST                   = 400,
    HTTP_401_UNAUTHORIZED                  = 401,
    HTTP_402_PAYMENT_REQUIRED              = 402,
    HTTP_403_FORBIDDEN                     = 403,
    HTTP_404_NOT_FOUND                     = 404,
    HTTP_405_METHOD_NOT_ALLOWED            = 405,
    HTTP_406_NOT_ACCEPTABLE                = 406,
    HTTP_407_PROXY_AUTHENTICATION_REQUIRED = 407,
    HTTP_408_REQUEST_TIMEOUT               = 408,
    HTTP_409_CONFLICT                      = 409,
    HTTP_410_GONE                          = 410,
    HTTP_411_LENGTH_REQUIRED               = 411,
    HTTP_412_PRECONDITION_FAILED           = 412,
    HTTP_413_PAYLOAD_TOO_LARGE             = 413,
    HTTP_414_URI_TOO_LONG                  = 414,
    HTTP_415_UNSUPPORTED_MEDIA_TYPE        = 415,
    HTTP_416_RANGE_NOT_SATISFIABLE         = 416,
    HTTP_417_EXPECTATION_FAILED            = 417,

    HTTP_426_UPGRADE_REQUIRED              = 426,

    /* 5xx */
    HTTP_500_INTERNAL_SERVER_ERROR         = 500,
    HTTP_501_NOT_IMPLEMENTED               = 501,
    HTTP_502_BAD_GATEWAY                   = 502,
    HTTP_503_SERVICE_UNAVAILABLE           = 503,
    HTTP_504_GATEWAY_TIMEOUT               = 504,
    HTTP_505_HTTP_VERSION_NOT_SUPPORTED    = 505,
};

/* Headers */
struct http_headers *http_headers_new(void);
void http_headers_delete(struct http_headers *);

size_t http_headers_nb_headers(struct http_headers *);
const char *http_headers_nth_header(struct http_headers *, size_t, const char **);
const char *http_headers_header(struct http_headers *, const char *);
bool http_headers_has_header(struct http_headers *, const char *);

void http_headers_add(struct http_headers *, const char *,
                              const char *);
void http_headers_add_nocopy(struct http_headers *, char *, char *);
void http_headers_set(struct http_headers *, const char *, const char *);
void http_headers_set_vprintf(struct http_headers *, const char *,
                              const char *, va_list);
void http_headers_set_printf(struct http_headers *, const char *,
                             const char *, ...)
    __attribute__ ((format(printf, 3, 4)));

/* Request */
struct http_request;

size_t http_request_nb_headers(const struct http_request *);
bool http_request_has_header(const struct http_request *, const char *);
const char *http_request_nth_header(const struct http_request *, size_t,
                                    const char **);
const char *http_request_header(const struct http_request *, const char *);

/* Router */
struct http_router;
struct http_server_conn;

typedef int (*http_route_cb)(struct http_server_conn *,
                             struct http_request *, void *);

struct http_router *http_router_new(void);
void http_router_delete(struct http_router *);

void http_router_bind(struct http_router *, const char *,
                      http_route_cb, void *);

/* Server */
struct http_server;

enum http_server_event {
    HTTP_SERVER_EVENT_TRACE,
    HTTP_SERVER_EVENT_ERROR,
    HTTP_SERVER_EVENT_LISTENING,
    HTTP_SERVER_EVENT_STOPPED,
};

typedef void (*http_server_event_cb)(struct http_server *,
                                     enum http_server_event, void *,
                                     void *);

struct http_server *http_server_new(struct io_base *);
void http_server_delete(struct http_server *);

void http_server_set_event_cb(struct http_server *,
                              http_server_event_cb, void *);

int http_server_listen(struct http_server *, const char *, uint16_t);
void http_server_stop(struct http_server *);

#endif
