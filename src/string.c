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

size_t
http_memspn(const void *data, size_t sz, const char *chars) {
    size_t nb_chars, count;
    const uint8_t *ptr;

    nb_chars = strlen(chars);
    ptr = data;
    count = 0;

    for (size_t i = 0; i < sz; i++) {
        for (size_t j = 0; j < nb_chars; j++) {
            if (ptr[i] == chars[j])
                goto next;
        }

        return count;

next:
        count++;
        continue;
    }

    return count;
}

size_t
http_memcspn(const void *data, size_t sz, const char *chars) {
    size_t nb_chars, count;
    const uint8_t *ptr;

    nb_chars = strlen(chars);
    ptr = data;
    count = 0;

    for (size_t i = 0; i < sz; i++) {
        for (size_t j = 0; j < nb_chars; j++) {
            if (ptr[i] == chars[j])
                return count;
        }

        count++;
    }

    return count;
}

void
http_string_vector_delete(struct c_ptr_vector *vector) {
    for (size_t i = 0; i < c_ptr_vector_length(vector); i++)
        c_free(c_ptr_vector_entry(vector, i));
    c_ptr_vector_delete(vector);
}
