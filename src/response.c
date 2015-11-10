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

static int http_response_preprocess_headers(struct http_response *);

struct http_response *
http_response_new(void) {
    struct http_response *response;

    response = c_malloc0(sizeof(struct http_response));

    response->version = HTTP_1_1;
    response->headers = http_headers_new();

    return response;
}

void
http_response_delete(struct http_response *response) {
    if (!response)
        return;

    c_free(response->reason);

    http_headers_delete(response->headers);

    c_free(response->body);

    c_vector_delete(response->content_codings);

    c_free0(response, sizeof(struct http_response));
}

int
http_response_parse(const char *data, size_t sz, uint32_t flags,
                    struct http_response **presponse, size_t *psz) {
    struct http_response *response;
    const char *ptr;
    size_t len, toklen;
    char status_string[4];
    size_t status_sz;
    int32_t status_value;
    int ret;

    ptr = data;
    len = sz;

#define HTTP_FAIL(fmt_, ...)                  \
    do {                                      \
        if (fmt_)                             \
            c_set_error(fmt_, ##__VA_ARGS__); \
        http_response_delete(response);       \
        return -1;                            \
    } while (0)

#define HTTP_TRUNCATED()                      \
    do {                                      \
        http_response_delete(response);       \
        return 0;                             \
    } while (0)

    response = http_response_new();

    /* Version */
    toklen = c_memcspn(ptr, len, " ");
    if (toklen == len) {
        if (len > HTTP_VERSION_MAX_LENGTH)
            HTTP_FAIL("invalid version");
        HTTP_TRUNCATED();
    }

    if (http_version_parse(ptr, toklen, &response->version) == -1)
        HTTP_FAIL(NULL);

    ptr += toklen + 1;
    len -= toklen + 1;

    /* Status */
    toklen = c_memcspn(ptr, len, " ");
    if (toklen == len) {
        if (len > 3)
            HTTP_FAIL("invalid status code");
        HTTP_TRUNCATED();
    }

    if (toklen > 3)
        HTTP_FAIL("invalid status code");

    memcpy(status_string, ptr, toklen);
    status_string[toklen] = '\0';

    if (c_parse_i32(status_string, &status_value, &status_sz) == -1)
        HTTP_FAIL("invalid status code");
    if (status_sz != toklen)
        HTTP_FAIL("invalid trailing data after status code");
    response->status = (enum http_status)status_value;

    ptr += toklen + 1;
    len -= toklen + 1;

    /* Reason */
    toklen = c_memcspn(ptr, len, "\r");
    if (toklen == len) {
        if (len > HTTP_REASON_MAX_LENGTH)
            HTTP_FAIL("reason string too long");
        HTTP_TRUNCATED();
    }

    response->reason = c_strndup(ptr, toklen);

    ptr += toklen;
    len -= toklen;

    /* End of status line */
    if (len < 2)
        HTTP_TRUNCATED();
    if (ptr[0] != '\r' || ptr[1] != '\n')
        HTTP_FAIL("malformed status line");

    ptr += 2;
    len -= 2;

    /* Headers */
    http_headers_delete(response->headers);
    response->headers = NULL;

    ret = http_headers_parse(ptr, len, &response->headers, NULL, &toklen);
    if (ret == -1)
        HTTP_FAIL(NULL);
    if (ret == 0)
        HTTP_TRUNCATED();

    ptr += toklen;
    len -= toklen;

    if (http_response_preprocess_headers(response) == -1) {
        http_response_delete(response);
        return -1;
    }

    /* Body */
    if (!http_response_can_have_body(response))
        goto end;

    if (response->has_content_length) {
        if (response->content_length > HTTP_RESPONSE_MAX_CONTENT_LENGTH)
            HTTP_FAIL("payload too large");

        if (len < response->content_length)
            HTTP_TRUNCATED();

        response->body_sz = response->content_length;
        response->body = c_strndup(ptr, response->content_length);

        ptr += response->body_sz;
        len -= response->body_sz;
    } else if (response->is_body_chunked) {
        struct http_headers *trailer;
        size_t chunked_data_sz;

        ret = http_chunked_data_parse(ptr, len,
                                      &response->body, &response->body_sz,
                                      &chunked_data_sz);
        if (ret == -1)
            HTTP_FAIL("invalid chunked body: %s", c_get_error());
        if (ret == 0)
            HTTP_TRUNCATED();
        printf("PARSED CHUNKED DATA %zu -> %zu\n", len, chunked_data_sz);

        ptr += chunked_data_sz;
        len -= chunked_data_sz;

        /* Trailer */
        ret = http_headers_parse(ptr, len, &trailer, NULL, &toklen);
        if (ret == -1)
            HTTP_FAIL(NULL);
        if (ret == 0)
            HTTP_TRUNCATED();

        http_headers_merge_nocopy(response->headers, trailer);
        http_headers_delete(trailer);

        ptr += toklen;
        len -= toklen;
    } else if (response->has_connection_close) {
        size_t content_length;

        if (flags & HTTP_RESPONSE_PARSE_EOF) {
            content_length = len;

            if (content_length > HTTP_RESPONSE_MAX_CONTENT_LENGTH)
                HTTP_FAIL("payload too large");

            response->body_sz = content_length;
            response->body = c_strndup(ptr, content_length);

            ptr += response->body_sz;
            len -= response->body_sz;
        } else {
            HTTP_TRUNCATED();
        }
    } else {
        HTTP_FAIL("missing content length");
    }

#undef HTTP_FAIL
#undef HTTP_TRUNCATED

end:
    *presponse = response;
    *psz = sz - len;
    return 1;
}

void
http_response_finalize(struct http_response *response) {
    char date[HTTP_RFC1123_DATE_BUFSZ];
    time_t now;

    /* Version */
    if (response->request)
        response->version = response->request->version;

    /* Date */
    now = time(NULL);
    http_format_timestamp(date, HTTP_RFC1123_DATE_BUFSZ, now);
    http_response_set_header(response, "Date", date);

    /* Content-Length */
    http_response_set_header_printf(response, "Content-Length", "%zu",
                                    response->body_sz);
}

void
http_response_to_buffer(const struct http_response *response,
                        struct c_buffer *buf) {
    const char *version_string, *status_string;

    version_string = http_version_to_string(response->version);
    assert(version_string);

    status_string = http_status_to_string(response->status);
    assert(status_string);

    /* Status line */
    c_buffer_add_printf(buf, "%s %d %s\r\n",
                        version_string, response->status, status_string);

    /* Headers */
    for (size_t i = 0; i < http_headers_nb_headers(response->headers); i++) {
        const char *name, *value;

        name = http_headers_nth_header(response->headers, i, &value);

        c_buffer_add_printf(buf, "%s: %s\r\n", name, value);
    }

    c_buffer_add_string(buf, "\r\n");

    /* Body */
    if (response->body)
        c_buffer_add(buf, response->body, response->body_sz);
}

struct http_request *
http_response_request(const struct http_response *response) {
    return response->request;
}

enum http_version
http_response_version(const struct http_response *response) {
    return response->version;
}

enum http_status
http_response_status(const struct http_response *response) {
    return response->status;
}

const char *
http_response_reason(const struct http_response *response) {
    return response->reason;
}

void
http_response_add_header(struct http_response *response,
                        const char *name, const char *value) {
    http_headers_add(response->headers, name, value);
}

void
http_response_add_header_nocopy(struct http_response *response,
                                const char *name, char *value) {
    http_headers_add_nocopy(response->headers, name, value);
}

void
http_response_set_header(struct http_response *response, const char *name,
                         const char *value) {
    http_headers_set(response->headers, name, value);
}

void
http_response_set_header_vprintf(struct http_response *response,
                                 const char *name,
                                 const char *fmt, va_list ap) {
    http_headers_set_vprintf(response->headers, name, fmt, ap);
}

void
http_response_set_header_printf(struct http_response *response,
                                const char *name,
                                const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    http_headers_set_vprintf(response->headers, name, fmt, ap);
    va_end(ap);
}

size_t
http_response_nb_headers(const struct http_response *response) {
    return http_headers_nb_headers(response->headers);
}

bool
http_response_has_header(const struct http_response *response, const char *name) {
    return http_headers_has_header(response->headers, name);
}

const char *
http_response_nth_header(const struct http_response *response, size_t idx,
                         const char **pvalue) {
    return http_headers_nth_header(response->headers, idx, pvalue);
}

const char *
http_response_header(const struct http_response *response, const char *name) {
    return http_headers_header(response->headers, name);
}

void *
http_response_body(const struct http_response *response, size_t *psz) {
    if (psz)
        *psz = response->body_sz;
    return response->body;
}

bool
http_response_can_have_body(const struct http_response *response) {
    if (response->status >= 100 && response->status < 200)
        return false;
    if (response->status == HTTP_204_NO_CONTENT)
        return false;
    if (response->status == HTTP_304_NOT_MODIFIED)
        return false;

    return true;
}

int
http_response_decode_body_gzip(struct http_response *response) {
    char *body;
    size_t body_sz;

    body = http_zlib_inflate(response->body, response->body_sz, &body_sz);
    if (!body)
        return -1;

    c_free(response->body);

    response->body = body;
    response->body_sz = body_sz;

    return 0;
}

size_t
http_response_nb_content_codings(const struct http_response *response) {
    if (!response->content_codings)
        return 0;

    return c_vector_length(response->content_codings);
}

enum http_content_coding
http_response_content_coding(const struct http_response *response,
                             size_t idx) {
    void *entry;

    entry = c_vector_entry(response->content_codings, idx);
    return *(enum http_content_coding *)entry;
}

void
http_response_remove_content_coding(const struct http_response *response,
                                    size_t idx) {
    c_vector_remove(response->content_codings, idx);
}

static int
http_response_preprocess_headers(struct http_response *response) {
#define HTTP_FAIL(fmt_, ...)                  \
    do {                                      \
        if (fmt_)                             \
            c_set_error(fmt_, ##__VA_ARGS__); \
        return -1;                            \
    } while (0)

    for (size_t i = 0; i < http_response_nb_headers(response); i++) {
        const char *name, *value;

        name = http_response_nth_header(response, i, &value);

#define HTTP_HEADER_IS(name_) (strcasecmp(name, name_) == 0)

        /* -- Content-Length ---------------------------------------------- */
        if (HTTP_HEADER_IS("Content-Length")) {
            response->has_content_length = true;

            if (c_parse_size(value, &response->content_length,
                             NULL) == -1) {
                HTTP_FAIL("cannot parse %s header: %s", name, c_get_error());
            }

        /* -- Content-Encoding -------------------------------------------- */
        } else if (HTTP_HEADER_IS("Content-Encoding")) {
            struct c_ptr_vector *tokens;

            tokens = http_list_parse(value);
            if (!tokens)
                HTTP_FAIL("cannot parse %s header: %s", name, c_get_error());

            response->content_codings = c_vector_new(
                sizeof(enum http_content_coding));

            for (size_t i = 0; i < c_ptr_vector_length(tokens); i++) {
                enum http_content_coding coding;
                const char *token;

                token = c_ptr_vector_entry(tokens, i);
                if (http_content_coding_parse(token, &coding) == -1) {
                    http_string_vector_delete(tokens);
                    HTTP_FAIL("unknown content coding '%s'", token);
                }

                c_vector_append(response->content_codings, &coding);
            }

            http_string_vector_delete(tokens);

        /* -- Connection -------------------------------------------------- */
        } else if (HTTP_HEADER_IS("Connection")) {
            if (strcasecmp(value, "close") == 0)
                response->has_connection_close = true;

        /* -- Transfer-Encoding ------------------------------------------- */
        } else if (HTTP_HEADER_IS("Transfer-Encoding")) {
            struct c_ptr_vector *tokens;

            tokens = http_list_parse(value);
            if (!tokens)
                HTTP_FAIL("cannot parse %s header: %s", name, c_get_error());

            for (size_t i = 0; i < c_ptr_vector_length(tokens); i++) {
                const char *token;

                token = c_ptr_vector_entry(tokens, i);

                if (strcasecmp(token, "chunked") == 0) {
                    response->is_body_chunked = true;
                } else if (strcasecmp(token, "compressed") == 0
                        || strcasecmp(token, "deflate") == 0
                        || strcasecmp(token, "gzip") == 0) {
                    http_string_vector_delete(tokens);
                    HTTP_FAIL("'%s' transfer coding not supported", token);
                } else {
                    http_string_vector_delete(tokens);
                    HTTP_FAIL("unknown transfer coding '%s'", token);
                }
            }

            http_string_vector_delete(tokens);
        }

#undef HTTP_HEADER_IS
    }

#undef HTTP_FAIL

    return 0;
}
