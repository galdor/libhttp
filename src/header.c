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
    http_headers_add_nocopy(headers, c_strdup(name), c_strdup(value));
}

void
http_headers_add_nocopy(struct http_headers *headers,
                        char *name, char *value) {
    struct http_header header;

    header.name = name;
    header.value = value;

    c_vector_append(headers->headers, &header);
}

void
http_headers_set(struct http_headers *headers,
                 const char *name, const char *value) {
    for (size_t i = 0; i < c_vector_length(headers->headers); i++) {
        struct http_header *header;

        header = c_vector_entry(headers->headers, i);

        if (strcasecmp(header->name, name) == 0) {
            c_free(header->value);
            header->value = c_strdup(value);
            return;
        }
    }

    http_headers_add(headers, name, value);
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
