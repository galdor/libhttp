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

static int http_request_preprocess_headers(struct http_request *,
                                           enum http_status *);

struct http_request *
http_request_new(void) {
    struct http_request *request;

    request = c_malloc0(sizeof(struct http_request));

    request->version = HTTP_1_1;
    request->headers = http_headers_new();

    return request;
}

void
http_request_delete(struct http_request *request) {
    if (!request)
        return;

    c_free(request->target);
    http_url_delete(request->target_url);
    http_path_delete(request->target_path);

    http_headers_delete(request->headers);

    c_free(request->body);

    if (request->named_parameters) {
        struct c_hash_table_iterator *it;
        char *name, *value;

        it = c_hash_table_iterate(request->named_parameters);
        while (c_hash_table_iterator_next(it, (void **)&name,
                                          (void **)&value) ==1) {
            c_free(name);
            c_free(value);
        }
        c_hash_table_iterator_delete(it);
        c_hash_table_delete(request->named_parameters);
    }

    http_auth_delete(request->auth);

    c_free0(request, sizeof(struct http_request));
}

int
http_request_parse(const char *data, size_t sz,
                   struct http_request **prequest, size_t *psz,
                   enum http_status *pstatus) {
    struct http_request *request;
    enum http_status status;
    const char *ptr;
    size_t len, toklen;
    int ret;

    ptr = data;
    len = sz;

#define HTTP_FAIL(status_, fmt_, ...)         \
    do {                                      \
        if (fmt_)                             \
            c_set_error(fmt_, ##__VA_ARGS__); \
        *pstatus = status_;                   \
        http_request_delete(request);         \
        return -1;                            \
    } while (0)

#define HTTP_TRUNCATED()                      \
    do {                                      \
        http_request_delete(request);         \
        return 0;                             \
    } while (0)

    request = http_request_new();

    /* Method */
    toklen = c_memcspn(ptr, len, " ");
    if (toklen == len) {
        if (len > HTTP_METHOD_MAX_LENGTH)
            HTTP_FAIL(HTTP_501_NOT_IMPLEMENTED, "unknown method");
        HTTP_TRUNCATED();
    }

    if (http_method_parse(ptr, toklen, &request->method) == -1)
        HTTP_FAIL(HTTP_501_NOT_IMPLEMENTED, NULL);

    ptr += toklen + 1;
    len -= toklen + 1;

    /* Target */
    toklen = c_memcspn(ptr, len, " ");
    if (toklen == len) {
        if (len > HTTP_REQUEST_TARGET_MAX_LENGTH)
            HTTP_FAIL(HTTP_414_URI_TOO_LONG, "request target too long");
        HTTP_TRUNCATED();
    }
    request->target = c_strndup(ptr, toklen);

    if (strcmp(request->target, "*") == 0) {
        if (request->method != HTTP_OPTIONS)
            HTTP_FAIL(HTTP_400_BAD_REQUEST, "invalid asterisk target");
    } else {
        struct http_url *url;
        struct http_path *path;
        const char *path_string;

        url = http_url_parse(request->target);
        if (!url) {
            HTTP_FAIL(HTTP_400_BAD_REQUEST, "invalid request target: %s",
                      c_get_error());
        }

        if (url->path) {
            path_string = url->path;
        } else {
            path_string = "/";
        }

        path = http_path_parse(path_string);
        if (!path) {
            HTTP_FAIL(HTTP_400_BAD_REQUEST, "invalid request target path: %s",
                      c_get_error());
        }

        request->target_url = url;
        request->target_path = path;
    }

    ptr += toklen + 1;
    len -= toklen + 1;

    /* Version */
    toklen = c_memcspn(ptr, len, "\r");
    if (toklen == len) {
        if (len > HTTP_VERSION_MAX_LENGTH)
            HTTP_FAIL(HTTP_400_BAD_REQUEST, "invalid version");
        HTTP_TRUNCATED();
    }

    if (http_version_parse(ptr, toklen, &request->version) == -1)
        HTTP_FAIL(HTTP_505_HTTP_VERSION_NOT_SUPPORTED, NULL);

    ptr += toklen;
    len -= toklen;

    /* End of request line */
    if (len < 2)
        HTTP_TRUNCATED();
    if (ptr[0] != '\r' || ptr[1] != '\n')
        HTTP_FAIL(HTTP_400_BAD_REQUEST, "malformed request line");

    ptr += 2;
    len -= 2;

    /* Headers */
    http_headers_delete(request->headers);
    request->headers = NULL;

    ret = http_headers_parse(ptr, len, &request->headers, &status, &toklen);
    if (ret == -1)
        HTTP_FAIL(status, NULL);
    if (ret == 0)
        HTTP_TRUNCATED();

    ptr += toklen;
    len -= toklen;

    if (http_request_preprocess_headers(request, pstatus) == -1) {
        http_request_delete(request);
        return -1;
    }

    /* Body */
    if (!http_request_can_have_body(request))
        goto end;

    if (request->has_content_length) {
        if (request->content_length > HTTP_REQUEST_MAX_CONTENT_LENGTH)
            HTTP_FAIL(HTTP_413_PAYLOAD_TOO_LARGE, "payload too large");

        if (len < request->content_length)
            HTTP_TRUNCATED();

        request->body_sz = request->content_length;
        request->body = c_strndup(ptr, request->content_length);

        ptr += request->body_sz;
        len -= request->body_sz;
    }

#undef HTTP_FAIL
#undef HTTP_TRUNCATED

end:
    *prequest = request;
    *psz = sz - len;
    return 1;
}

enum http_method
http_request_method(const struct http_request *request) {
    return request->method;
}

struct http_url *
http_request_target_url(const struct http_request *request) {
    return request->target_url;
}

void
http_request_set_target_url(struct http_request *request,
                            const struct http_url *url) {
    http_url_delete(request->target_url);
    request->target_url = http_url_clone(url);
}

struct http_server_conn *
http_request_server_conn(const struct http_request *request) {
    return request->conn;
}

void
http_request_set_headers_nocopy(struct http_request *request,
                                struct http_headers *headers) {
    http_headers_delete(request->headers);
    request->headers = headers;
}

void
http_request_set_headers(struct http_request *request,
                         const struct http_headers *headers) {
    http_request_set_headers_nocopy(request, http_headers_clone(headers));
}

void
http_request_add_header(struct http_request *request,
                        const char *name, const char *value) {
    http_request_add_header_nocopy(request, name, c_strdup(value));
}

void
http_request_add_header_nocopy(struct http_request *request,
                               const char *name, char *value) {
    http_headers_add_nocopy(request->headers, name, value);
}

void
http_request_set_header(struct http_request *request, const char *name,
                        const char *value) {
    http_headers_set(request->headers, name, value);
}

void
http_request_set_header_vprintf(struct http_request *request,
                                const char *name,
                                const char *fmt, va_list ap) {
    http_headers_set_vprintf(request->headers, name, fmt, ap);
}

void
http_request_set_header_printf(struct http_request *request,
                               const char *name,
                               const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    http_headers_set_vprintf(request->headers, name, fmt, ap);
    va_end(ap);
}

struct http_headers *
http_request_headers(const struct http_request *request) {
    return request->headers;
}

size_t
http_request_nb_headers(const struct http_request *request) {
    return http_headers_nb_headers(request->headers);
}

bool
http_request_has_header(const struct http_request *request, const char *name) {
    return http_headers_has_header(request->headers, name);
}

const char *
http_request_nth_header(const struct http_request *request, size_t idx,
                        const char **pvalue) {
    return http_headers_nth_header(request->headers, idx, pvalue);
}

const char *
http_request_header(const struct http_request *request, const char *name) {
    return http_headers_header(request->headers, name);
}

size_t
http_request_body_size(const struct http_request *request) {
    return request->body_sz;
}

void *
http_request_body(const struct http_request *request, size_t *psz) {
    if (psz)
        *psz = request->body_sz;
    return request->body;
}

const char *
http_request_named_parameter(const struct http_request *request,
                             const char *name) {
    const char *value;

    if (!request->named_parameters)
        return NULL;

    if (c_hash_table_get(request->named_parameters, name, (void **)&value) == 0)
        return NULL;

    return value;
}

bool
http_request_has_auth_data(const struct http_request *request) {
    return request->auth != NULL;
}

enum http_auth_scheme
http_request_auth_scheme(const struct http_request *request) {
    assert(request->auth);

    return request->auth->scheme;
}

void
http_request_basic_auth_data(const struct http_request *request,
                             const char **puser, const char **ppassword) {
    assert(request->auth);
    assert(request->auth->scheme == HTTP_AUTH_SCHEME_BASIC);

    *puser = request->auth->u.basic.user;
    *ppassword = request->auth->u.basic.password;
}

size_t
http_request_nb_query_parameters(const struct http_request *request) {
    return http_url_nb_query_parameters(request->target_url);
}

const char *
http_request_nth_query_parameter(const struct http_request *request,
                                 size_t idx, const char **pvalue) {
    return http_url_nth_query_parameter(request->target_url, idx, pvalue);
}

bool
http_request_has_query_parameter(const struct http_request *request,
                                 const char *name, const char **pvalue) {
    return http_url_has_query_parameter(request->target_url, name, pvalue);
}

const char *
http_request_query_parameter(const struct http_request *request,
                             const char *name) {
    return http_url_query_parameter(request->target_url, name);
}

struct c_ptr_vector *
http_request_accepted_media_types(const struct http_request *request) {
    struct c_ptr_vector *media_types;

    media_types = c_ptr_vector_new();

    for (size_t h = 0; h < http_headers_nb_headers(request->headers); h++) {
        struct c_ptr_vector *entries;
        const char *name, *value;

        name = http_headers_nth_header(request->headers, h, &value);
        if (strcasecmp(name, "accept") != 0)
            continue;

        entries = http_list_parse(value);
        if (!entries) {
            c_set_error("invalid Accept header: %s", c_get_error());
            c_ptr_vector_delete(media_types);
            return NULL;
        }

        for (size_t i = 0; i < c_ptr_vector_length(entries); i++) {
            struct http_media_type *media_type;
            const char *entry;

            entry = c_ptr_vector_entry(entries, i);

            media_type = http_media_type_parse(entry);
            if (!media_type) {
                c_set_error("invalid media type: %s", c_get_error());

                http_string_vector_delete(entries);
                for (size_t j = 0; j < c_ptr_vector_length(media_types); j++)
                    http_media_type_delete(c_ptr_vector_entry(media_types, j));
                c_ptr_vector_delete(media_types);
                return NULL;
            }

            c_ptr_vector_append(media_types, media_type);
        }

        http_string_vector_delete(entries);
    }

    return media_types;
}

int
http_request_accepts_media_type(const struct http_request *request,
                                const char *type, const char *subtype) {
    int nb_accept_headers;

    nb_accept_headers = 0;

    for (size_t h = 0; h < http_headers_nb_headers(request->headers); h++) {
        struct c_ptr_vector *entries;
        const char *name, *value;

        name = http_headers_nth_header(request->headers, h, &value);
        if (strcasecmp(name, "accept") != 0)
            continue;

        nb_accept_headers++;

        entries = http_list_parse(value);
        if (!entries) {
            c_set_error("invalid Accept header: %s", c_get_error());
            return -1;
        }

        for (size_t i = 0; i < c_ptr_vector_length(entries); i++) {
            struct http_media_type *media_type;
            const char *entry;

            entry = c_ptr_vector_entry(entries, i);

            media_type = http_media_type_parse(entry);
            if (!media_type) {
                c_set_error("invalid media type in Accept header: %s",
                            c_get_error());

                http_string_vector_delete(entries);
                return -1;
            }

            if (strcmp(media_type->type, "*") == 0
             || strcmp(media_type->type, type) == 0) {
                /* Type match */

                if (strcmp(media_type->subtype, "*") == 0
                 || strcmp(media_type->subtype, subtype) == 0) {
                    /* Subtype match */

                    http_media_type_delete(media_type);
                    http_string_vector_delete(entries);
                    return 1;
                }
            }

            http_media_type_delete(media_type);
        }

        http_string_vector_delete(entries);
    }

    if (nb_accept_headers == 0)
        return 1;

    return 0;
}

bool
http_request_can_have_body(const struct http_request *request) {
    return request->method == HTTP_POST
        || request->method == HTTP_PUT;
}

bool
http_request_close_connection(const struct http_request *request) {
    if (request->version == HTTP_1_0) {
        return !(request->connection_options & HTTP_CONNECTION_KEEP_ALIVE);
    } else {
        return (request->connection_options & HTTP_CONNECTION_CLOSE);
    }
}

static int
http_request_preprocess_headers(struct http_request *request,
                                enum http_status *pstatus) {
    bool has_host;

#define HTTP_FAIL(status_, fmt_, ...)         \
    do {                                      \
        if (fmt_)                             \
            c_set_error(fmt_, ##__VA_ARGS__); \
        *pstatus = status_;                   \
        return -1;                            \
    } while (0)

    has_host = false;

    for (size_t i = 0; i < http_request_nb_headers(request); i++) {
        const char *name, *value;

        name = http_request_nth_header(request, i, &value);

#define HTTP_HEADER_IS(name_) (strcasecmp(name, name_) == 0)

        /* -- Host -------------------------------------------------------- */
        if (HTTP_HEADER_IS("Host")) {
            has_host = true;

            /* TODO check if the value is a hostname we are listening on */

        /* -- Content-Length ---------------------------------------------- */
        } else if (HTTP_HEADER_IS("Content-Length")) {
            request->has_content_length = true;

            if (c_parse_size(value, &request->content_length,
                             NULL) == -1) {
                HTTP_FAIL(HTTP_400_BAD_REQUEST, "cannot parse %s header: %s",
                          name, c_get_error());
            }

        /* -- Transfer-Encoding ------------------------------------------- */
        } else if (HTTP_HEADER_IS("Transfer-Encoding")) {
            struct c_ptr_vector *tokens;

            tokens = http_list_parse(value);
            if (!tokens) {
                HTTP_FAIL(HTTP_400_BAD_REQUEST, "cannot parse %s header: %s",
                          name, c_get_error());
            }

            for (size_t i = 0; i < c_ptr_vector_length(tokens); i++) {
                const char *token;

                token = c_ptr_vector_entry(tokens, i);

                if (strcasecmp(token, "chunked") == 0
                 || strcasecmp(token, "compressed") == 0
                 || strcasecmp(token, "deflate") == 0
                 || strcasecmp(token, "gzip") == 0) {
                    http_string_vector_delete(tokens);
                    HTTP_FAIL(HTTP_501_NOT_IMPLEMENTED,
                              "'%s' transfer coding not supported", token);
                } else {
                    http_string_vector_delete(tokens);
                    HTTP_FAIL(HTTP_501_NOT_IMPLEMENTED,
                              "unknown transfer coding '%s'", token);
                }
            }

            http_string_vector_delete(tokens);

        /* -- Connection -------------------------------------------------- */
        } else if (HTTP_HEADER_IS("Connection")) {
            struct c_ptr_vector *tokens;

            tokens = http_list_parse(value);
            if (!tokens) {
                HTTP_FAIL(HTTP_400_BAD_REQUEST, "cannot parse %s header: %s",
                          name, c_get_error());
            }

            for (size_t i = 0; i < c_ptr_vector_length(tokens); i++) {
                const char *token;

                token = c_ptr_vector_entry(tokens, i);

                if (strcasecmp(token, "close") == 0) {
                    request->connection_options |= HTTP_CONNECTION_CLOSE;
                } else if (strcasecmp(token, "keep-alive") == 0) {
                    request->connection_options |= HTTP_CONNECTION_KEEP_ALIVE;
                } else {
                    HTTP_FAIL(HTTP_501_NOT_IMPLEMENTED,
                              "unknown connection option '%s'", token);
                }
            }

            http_string_vector_delete(tokens);

        /* -- Authorization ----------------------------------------------- */
        } else if (HTTP_HEADER_IS("Authorization")) {
            request->auth = http_auth_parse_authorization(value);
            if (!request->auth) {
                HTTP_FAIL(HTTP_400_BAD_REQUEST,
                          "cannot parse authorization header: %s", c_get_error());
            }
        }

#undef HTTP_HEADER_IS
    }

    if (request->version == HTTP_1_1 && !has_host)
        HTTP_FAIL(HTTP_400_BAD_REQUEST, "missing Host header");

#undef HTTP_FAIL

    return 0;
}

void
http_request_extract_named_parameters(struct http_request *request,
                                      const struct http_route *route) {
    const struct http_path *path, *rpath;
    size_t nb_segments;

    assert(!request->named_parameters);
    request->named_parameters = c_hash_table_new(c_hash_string, c_equal_string);

    path = request->target_path;
    rpath = route->path;

    assert(http_path_nb_segments(path) == http_path_nb_segments(rpath));
    nb_segments = http_path_nb_segments(path);

    for (size_t i = 0; i < nb_segments; i++) {
        const char *segment, *rsegment;

        segment = http_path_segment(path, i);
        rsegment = http_path_segment(rpath, i);

        if (rsegment[0] == ':') {
            const char *name, *value;

            name = rsegment + 1;
            value = segment;

            c_hash_table_insert(request->named_parameters,
                                c_strdup(name), c_strdup(value));
        }
    }
}

void
http_request_finalize(struct http_request *request,
                      struct http_client *client) {
    struct http_url *url;
    const char *host;
    uint16_t port;
    bool is_default_port;

    url = request->target_url;

    /* Host */
    host = url->host ? url->host : http_client_host(client);
    port = url->port ? url->port_number : http_client_port(client);

    if (io_tcp_client_is_ssl_enabled(client->tcp_client)) {
        is_default_port = (port == 443);
    } else {
        is_default_port = (port == 80);
    }

    if (is_default_port) {
        http_request_set_header_printf(request, "Host", "%s", host);
    } else {
        http_request_set_header_printf(request, "Host", "%s:%u", host, port);
    }

    /* Content-Length */
    if (http_request_can_have_body(request) || request->body) {
        http_request_set_header_printf(request, "Content-Length", "%zu",
                                       request->body_sz);
    }
}

void
http_request_to_buffer(const struct http_request *request,
                       struct c_buffer *buf) {
    const char *method_string, *version_string;

    /* Status line */
    method_string = http_method_to_string(request->method);
    assert(method_string);
    c_buffer_add_printf(buf, "%s ", method_string);

    http_url_to_buffer(request->target_url, buf);

    version_string = http_version_to_string(request->version);
    assert(version_string);
    c_buffer_add_printf(buf, " %s\r\n", version_string);

    /* Headers */
    for (size_t i = 0; i < http_headers_nb_headers(request->headers); i++) {
        const char *name, *value;

        name = http_headers_nth_header(request->headers, i, &value);

        c_buffer_add_printf(buf, "%s: %s\r\n", name, value);
    }

    c_buffer_add_string(buf, "\r\n");

    /* Body */
    if (request->body)
        c_buffer_add(buf, request->body, request->body_sz);
}
