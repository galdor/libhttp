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

void *
http_zlib_inflate(const uint8_t *idata, size_t isize, size_t *posize) {
    static const size_t window_size = 4096;

    struct c_buffer *buf;
    uint8_t window[window_size];
    z_stream stream;
    uint8_t *odata;
    int ret;

    assert(isize <= UINT_MAX);

    memset(&stream, 0, sizeof(z_stream));
    ret = inflateInit2(&stream, 15 + 32); /* support zlib/gzip decoding
                                           * do not ask... */
    if (ret != Z_OK) {
        c_set_error("cannot initialize stream: %s", zError(ret));
        return NULL;
    }

    buf = c_buffer_new();

    stream.next_in = (unsigned char *)idata;
    stream.avail_in = isize;

    for (;;) {
        size_t inflated_size;

        stream.next_out = window;
        stream.avail_out = window_size;

        ret = inflate(&stream, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            c_set_error("cannot inflate data: %s", zError(ret));
            c_buffer_delete(buf);
            return NULL;
        }

        inflated_size = window_size - stream.avail_out;
        c_buffer_add(buf, window, inflated_size);

        if (ret == Z_STREAM_END)
            break;
    }

    inflateEnd(&stream);

    odata = c_buffer_extract(buf, posize);
    c_buffer_delete(buf);

    return odata;
}
