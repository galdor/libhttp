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

struct http_headers *
http_headers_new(void) {
    struct http_headers *headers;

    headers = c_malloc0(sizeof(struct http_headers));

    headers->headers = c_vector_new(sizeof(struct http_header));

    return headers;
}

void
http_headers_delete(struct http_headers *headers) {
    if (!headers)
        return;

    for (size_t i = 0; i < c_vector_length(headers->headers); i++) {
        struct http_header *header;

        header = c_vector_entry(headers->headers, i);

        c_free(header->name);
        c_free(header->value);
    }
    c_vector_delete(headers->headers);

    c_free0(headers, sizeof(struct http_headers));
}

struct http_headers *
http_headers_clone(const struct http_headers *headers) {
    struct http_headers *nheaders;

    nheaders = http_headers_new();

    for (size_t i = 0; i < c_vector_length(headers->headers); i++) {
        struct http_header *header;

        header = c_vector_entry(headers->headers, i);

        http_headers_add(nheaders, header->name, header->value);
    }

    return nheaders;
}

int
http_headers_parse(const char *data, size_t sz, struct http_headers **pheaders,
                   enum http_status *pstatus, size_t *psz) {
    struct http_headers *headers;
    const char *ptr;
    size_t len, toklen;

    ptr = data;
    len = sz;

#define HTTP_FAIL(status_, fmt_, ...)         \
    do {                                      \
        if (fmt_)                             \
            c_set_error(fmt_, ##__VA_ARGS__); \
        if (pstatus)                          \
          *pstatus = status_;                 \
        http_headers_delete(headers);         \
        return -1;                            \
    } while (0)

#define HTTP_TRUNCATED()                      \
    do {                                      \
        http_headers_delete(headers);         \
        return 0;                             \
    } while (0)

    headers = http_headers_new();

    while (len > 0) {
        const char *name_start, *value_start;
        size_t name_length, value_length;
        char *name, *value;

        if (len >= 2 && ptr[0] == '\r' && ptr[1] == '\n') {
            ptr += 2;
            len -= 2;
            break;
        } else if (len >= 1 && ptr[0] == '\r') {
            HTTP_TRUNCATED();
        }

        /* Name */
        toklen = c_memcspn(ptr, len, ":");
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
        toklen = c_memcspn(ptr, len, "\r");
        if (toklen == len) {
            if (len > HTTP_HEADER_VALUE_MAX_LENGTH)
                HTTP_FAIL(HTTP_400_BAD_REQUEST, "header value too long");
            HTTP_TRUNCATED();
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

        http_headers_add_nocopy(headers, name, value);
        c_free(name);

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

#undef HTTP_FAIL
#undef HTTP_TRUNCATED

    *pheaders = headers;
    *psz = sz - len;
    return 1;
}

size_t
http_headers_nb_headers(struct http_headers *headers) {
    return c_vector_length(headers->headers);
}

const char *
http_headers_nth_header(struct http_headers *headers, size_t idx,
                        const char **pvalue) {
    const struct http_header *header;

    header = c_vector_entry(headers->headers, idx);

    *pvalue = header->value;
    return header->name;
}

const char *
http_headers_header(struct http_headers *headers, const char *name) {
    for (size_t i = 0; i < c_vector_length(headers->headers); i++) {
        struct http_header *header;

        header = c_vector_entry(headers->headers, i);

        if (strcasecmp(header->name, name) == 0)
            return header->value;
    }

    return NULL;
}

bool
http_headers_has_header(struct http_headers *headers, const char *name) {
    for (size_t i = 0; i < c_vector_length(headers->headers); i++) {
        struct http_header *header;

        header = c_vector_entry(headers->headers, i);

        if (strcasecmp(header->name, name) == 0)
            return true;
    }

    return false;
}

void
http_headers_add(struct http_headers *headers,
                 const char *name, const char *value) {
    http_headers_add_nocopy(headers, name, c_strdup(value));
}

void
http_headers_add_nocopy(struct http_headers *headers,
                        const char *name, char *value) {
    struct http_header header;

    header.name = c_strdup(name);
    header.value = value;

    c_vector_append(headers->headers, &header);
}

void
http_headers_set(struct http_headers *headers,
                 const char *name, const char *value) {
    return http_headers_set_nocopy(headers, name, c_strdup(value));
}

void
http_headers_set_nocopy(struct http_headers *headers,
                        const char *name, char *value) {
    for (size_t i = 0; i < c_vector_length(headers->headers); i++) {
        struct http_header *header;

        header = c_vector_entry(headers->headers, i);

        if (strcasecmp(header->name, name) == 0) {
            c_free(header->value);
            header->value = value;
            return;
        }
    }

    http_headers_add_nocopy(headers, name, value);
}

void
http_headers_set_vprintf(struct http_headers *headers,
                         const char *name, const char *fmt, va_list ap) {
    char *value;

    c_vasprintf(&value, fmt, ap);
    http_headers_set(headers, name, value);
    c_free(value);
}

void
http_headers_set_header_printf(struct http_headers *headers,
                                const char *name, const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    http_headers_set_vprintf(headers, name, fmt, ap);
    va_end(ap);
}

void
http_headers_merge_nocopy(struct http_headers *headers,
                          struct http_headers *src) {
    for (size_t i = 0; i < c_vector_length(src->headers); i++) {
        struct http_header *header;

        header = c_vector_entry(src->headers, i);

        http_headers_set_nocopy(headers, header->name, header->value);
        c_free(header->name);
    }

    c_vector_clear(src->headers);
}
