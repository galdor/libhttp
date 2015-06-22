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

int
http_chunked_data_parse(const void *data, size_t sz,
                        void **pbody, size_t *p_body_sz,
                        size_t *psz) {
    struct c_buffer *buf;
    const char *ptr;
    size_t len, toklen;

    ptr = data;
    len = sz;

    buf = c_buffer_new();

#define HTTP_FAIL(fmt_, ...)                  \
    do {                                      \
        if (fmt_)                             \
            c_set_error(fmt_, ##__VA_ARGS__); \
        c_buffer_delete(buf);                 \
        return -1;                            \
    } while (0)

#define HTTP_TRUNCATED()                      \
    do {                                      \
        c_buffer_delete(buf);                 \
        return 0;                             \
    } while (0)

    for (;;) {
        unsigned long long ull;
        size_t chunk_sz;
        char tmp[32];

        /* Chunk size */
        /* We ignore extensions */
        toklen = c_memcspn(ptr, len, "\r");
        if (toklen == len)
            HTTP_TRUNCATED();

        if (toklen >= sizeof(tmp))
            HTTP_FAIL("chunk size too long");

        memcpy(tmp, ptr, toklen);
        tmp[toklen] = '\0';

        errno = 0;
        ull = strtoull(tmp, NULL, 16);
        if (errno)
            HTTP_FAIL("cannot parse chunk size: %s", strerror(errno));
        if (ull > SIZE_MAX)
            HTTP_FAIL("chunk too large");

        chunk_sz = (size_t)ull;

        if (c_buffer_length(buf) + chunk_sz > HTTP_RESPONSE_MAX_CONTENT_LENGTH)
            HTTP_FAIL("payload too large");

        ptr += toklen;
        len -= toklen;

        /* End of chunk size line */
        if (len < 2)
            HTTP_TRUNCATED();
        if (ptr[0] != '\r' || ptr[1] != '\n')
            HTTP_FAIL("malformed status line");

        ptr += 2;
        len -= 2;

        /* Chunk data */
        if (chunk_sz > len)
            HTTP_TRUNCATED();

        c_buffer_add(buf, ptr, chunk_sz);

        ptr += chunk_sz;
        len -= chunk_sz;

        /* End of chunk data */
        if (len < 2)
            HTTP_TRUNCATED();
        if (ptr[0] != '\r' || ptr[1] != '\n')
            HTTP_FAIL("malformed status line");

        ptr += 2;
        len -= 2;

        if (chunk_sz == 0) {
            /* Last chunk */
            break;
        }

        if (len == 0)
            HTTP_TRUNCATED();
    }

#undef HTTP_FAIL
#undef HTTP_TRUNCATED

    *pbody = c_buffer_extract_string(buf, p_body_sz);
    c_buffer_delete(buf);

    if (psz)
        *psz = sz - len;
    return 1;
}
