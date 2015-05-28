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

struct http_path *
http_path_new(void) {
    struct http_path *path;

    path = c_malloc0(sizeof(struct http_path));

    path->segments = c_ptr_vector_new();

    return path;
}

void
http_path_delete(struct http_path *path) {
    if (!path)
        return;

    for (size_t i = 0; i < c_ptr_vector_length(path->segments); i++)
        c_free(c_ptr_vector_entry(path->segments, i));
    c_ptr_vector_delete(path->segments);

    c_free0(path, sizeof(struct http_path));
}

struct http_path *
http_path_parse(const char *string) {
    struct http_path *path;
    const char *ptr, *start;

    path = http_path_new();

    ptr = string;
    if (*ptr != '/') {
        c_set_error("invalid first path character");
        goto error;
    }

    ptr++;
    start = ptr;

    for (;;) {
        if (*ptr == '\0' || *ptr == '/') {
            size_t toklen;

            toklen = (size_t)(ptr - start);
            if (*ptr == '/' && toklen == 0) {
                c_set_error("empty path component");
                goto error;
            }

            if (*ptr == '/' || toklen > 0)
                http_path_add_segment2(path, start, toklen);

            if (*ptr == '\0')
                break;

            ptr++;
            start = ptr;
        } else {
            ptr++;
        }
    }

    return path;

error:
    http_path_delete(path);
    return NULL;
}

size_t
http_path_nb_segments(const struct http_path *path) {
    return c_ptr_vector_length(path->segments);
}

const char *
http_path_segment(const struct http_path *path, size_t idx) {
    return c_ptr_vector_entry(path->segments, idx);
}

void
http_path_add_segment(struct http_path *path, const char *segment) {
    c_ptr_vector_append(path->segments, c_strdup(segment));
}

void
http_path_add_segment2(struct http_path *path, const char *data, size_t sz) {
    c_ptr_vector_append(path->segments, c_strndup(data, sz));
}
