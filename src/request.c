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

    request->headers = http_headers_new();

    return request;
}

void
http_request_delete(struct http_request *request) {
    if (!request)
        return;

    c_free(request->target);
    http_uri_delete(request->target_uri);
    http_path_delete(request->target_path);

    http_headers_delete(request->headers);

    c_free(request->body);

    c_free0(request, sizeof(struct http_request));
}

int
http_request_parse(const char *data, size_t sz,
                   struct http_request **prequest, size_t *psz,
                   enum http_status *pstatus) {
    struct http_request *request;
    const char *ptr;
    size_t len, toklen;

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
    toklen = strcspn(ptr, " ");
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
    toklen = strcspn(ptr, " ");
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
        struct http_uri *uri;
        struct http_path *path;

        uri = http_uri_parse(request->target);
        if (!uri) {
            HTTP_FAIL(HTTP_400_BAD_REQUEST, "invalid request target: %s",
                      c_get_error());
        }

        path = http_path_parse(uri->path);
        if (!path) {
            HTTP_FAIL(HTTP_400_BAD_REQUEST, "invalid request target path: %s",
                      c_get_error());
        }

        request->target_uri = uri;
        request->target_path = path;
    }

    ptr += toklen + 1;
    len -= toklen + 1;

    /* Version */
    toklen = strcspn(ptr, "\r");
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
    for (;;) {
        const char *name_start, *value_start;
        size_t name_length, value_length;
        char *name, *value;

        if (len >= 2 && ptr[0] == '\r' && ptr[1] == '\n') {
            ptr += 2;
            len -= 2;
            break;
        }

        /* Name */
        toklen = strcspn(ptr, ":");
        if (toklen == len) {
            if (len > HTTP_HEADER_NAME_MAX_LENGTH)
                HTTP_FAIL(HTTP_400_BAD_REQUEST, "header name too long");
            HTTP_TRUNCATED();
        } else if (toklen == 0) {
            HTTP_FAIL(HTTP_400_BAD_REQUEST, "empty header name");
        }

        if (ptr[toklen - 1] == ' ' || ptr[toklen - 1] == '\t')
            HTTP_FAIL(HTTP_400_BAD_REQUEST, "trailing space after header name");

        name_start = ptr;
        name_length = toklen;

        ptr += toklen + 1;
        len -= toklen + 1;

        while (len > 0 && (ptr[0] == ' ' || ptr[0] == '\t')) {
            ptr++;
            len--;
        }

        /* Value */
        toklen = strcspn(ptr, "\r");
        if (toklen == len) {
            if (len > HTTP_HEADER_VALUE_MAX_LENGTH)
                HTTP_FAIL(HTTP_400_BAD_REQUEST, "header value too long");
            HTTP_TRUNCATED();
        } else if (toklen == 0) {
            HTTP_FAIL(HTTP_400_BAD_REQUEST, "empty header value");
        }

        value_start = ptr;
        value_length = toklen;

        while (value_length > 0) {
            if (ptr[value_length - 1] == ' '
             || ptr[value_length - 1] == '\t') {
                value_length--;
            } else {
                break;
            }
        }

        ptr += toklen;
        len -= toklen;

        /* Header */
        name = c_strndup(name_start, name_length);
        value = c_strndup(value_start, value_length);

        http_request_add_header_nocopy(request, name, value);

        /* End of header */
        if (len < 2)
            HTTP_TRUNCATED();
        if (ptr[0] != '\r' || ptr[1] != '\n')
            HTTP_FAIL(HTTP_400_BAD_REQUEST, "malformed header");

        ptr += 2;
        len -= 2;

        if (len > 0 && (ptr[0] == ' ' || ptr[0] == '\t'))
            HTTP_FAIL(HTTP_400_BAD_REQUEST, "obsolete folded header value");
    }

    if (http_request_preprocess_headers(request, pstatus) == -1) {
        http_request_delete(request);
        return -1;
    }

    /* Body */
    if (!http_request_can_have_body(request))
        goto end;

    if (!request->has_content_length)
        HTTP_FAIL(HTTP_411_LENGTH_REQUIRED, "missing Content-Length header");

    if (request->content_length > HTTP_REQUEST_MAX_CONTENT_LENGTH)
        HTTP_FAIL(HTTP_413_PAYLOAD_TOO_LARGE, "payload too large");

    if (len < request->content_length)
        HTTP_TRUNCATED();

    request->body_sz = request->content_length;
    request->body = c_strndup(ptr, request->content_length);

    ptr += request->body_sz;
    len -= request->body_sz;

#undef HTTP_FAIL
#undef HTTP_TRUNCATED

end:
    *prequest = request;
    *psz = sz - len;
    return 1;
}

void
http_request_add_header(struct http_request *request,
                        const char *name, const char *value) {
    http_request_add_header_nocopy(request, c_strdup(name), c_strdup(value));
}

void
http_request_add_header_nocopy(struct http_request *request,
                               char *name, char *value) {
    http_headers_add_nocopy(request->headers, name, value);
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

const char *
http_request_path_segment(const struct http_request *request, size_t idx) {
    return http_path_segment(request->target_path, idx);
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
                    HTTP_FAIL(HTTP_501_NOT_IMPLEMENTED,
                              "'%s' transfer coding not supported", token);
                } else {
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
        }

#undef HTTP_HEADER_IS
    }

    if (request->version == HTTP_1_1 && !has_host)
        HTTP_FAIL(HTTP_400_BAD_REQUEST, "missing Host header");

#undef HTTP_FAIL

    return 0;
}
