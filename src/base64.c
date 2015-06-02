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

/* See RFC 4648 */

uint8_t *
http_base64_decode(const void *data, size_t sz, size_t *pdsz) {
    static const int8_t bytes[256] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 00 - 0f */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 10 - 1f */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, /* 20 - 2f */
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, /* 30 - 3f */
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, /* 40 - 4f */
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, /* 50 - 5f */
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, /* 60 - 6f */
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, /* 70 - 7f */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 80 - 8f */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* 90 - 9f */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* a0 - af */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* b0 - bf */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* c0 - cf */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* d0 - df */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* e0 - ef */
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, /* f0 - ff */
    };

    int8_t a, b, c, d;
    size_t decoded_sz;
    uint8_t *decoded_data, *optr;
    const uint8_t *iptr;
    size_t nb_groups;

    if (sz % 4 != 0) {
        c_set_error("trailing data");
        return NULL;
    }

    iptr = (const uint8_t *)data;

    nb_groups = sz / 4;
    decoded_sz = nb_groups * 3;
    if (sz > 0 && iptr[sz - 1] == '=') {
        if (sz > 1 && iptr[sz - 2] == '=') {
            decoded_sz -= 2;
        } else {
            decoded_sz -= 1;
        }
    }

    decoded_data = c_malloc(decoded_sz);
    optr = decoded_data;

    if (nb_groups > 1) {
        for (size_t i = 0; i < nb_groups - 1; i++) {
            /* +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
             * |a|a|a|a|a|a|b|b| |b|b|b|b|c|c|c|c| |c|c|d|d|d|d|d|d|
             * +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
             */

            a = bytes[iptr[0]];
            b = bytes[iptr[1]];
            c = bytes[iptr[2]];
            d = bytes[iptr[3]];

            if (a == -1 || b == -1 || c == -1 || d == -1) {
                c_set_error("invalid base64 character");
                goto error;
            }

            *optr++ = (uint8_t)((a << 2) | (b >> 4));
            *optr++ = (uint8_t)((b << 4) | (c >> 2));
            *optr++ = (uint8_t)((c << 6) | d);

            iptr += 4;
        }
    }

    if (nb_groups > 0) {
        switch (nb_groups * 3 - decoded_sz) {
        case 0:
            a = bytes[iptr[0]];
            b = bytes[iptr[1]];
            c = bytes[iptr[2]];
            d = bytes[iptr[3]];

            if (a == -1 || b == -1 || c == -1 || d == -1) {
                c_set_error("invalid base64 character");
                goto error;
            }

            *optr++ = (uint8_t)((a << 2) | (b >> 4));
            *optr++ = (uint8_t)((b << 4) | (c >> 2));
            *optr++ = (uint8_t)((c << 6) | d);
            break;

        case 1:
            if (iptr[3] != '=') {
                c_set_error("invalid padding");
                goto error;
            }

            a = bytes[iptr[0]];
            b = bytes[iptr[1]];
            c = bytes[iptr[2]];

            if (a == -1 || b == -1 || c == -1) {
                c_set_error("invalid base64 character");
                goto error;
            }

            *optr++ = (uint8_t)((a << 2) | (b >> 4));
            *optr++ = (uint8_t)((b << 4) | (c >> 2));
            break;

        case 2:
            if (iptr[2] != '=' || iptr[3] != '=') {
                c_set_error("invalid padding");
                goto error;
            }

            a = bytes[iptr[0]];
            b = bytes[iptr[1]];

            if (a == -1 || b == -1) {
                c_set_error("invalid base64 character");
                goto error;
            }

            *optr++ = (uint8_t)((a << 2) | (b >> 4));
            break;
        }
    }

    if (pdsz)
        *pdsz = decoded_sz;
    return decoded_data;

error:
    c_free(decoded_data);
    return NULL;
}

uint8_t *
http_base64_encode(const void *data, size_t sz, size_t *pesz) {
    static const uint8_t chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
                                   "ghijklmnopqrstuvwxyz0123456789+/";

    uint8_t a, b, c, d;
    size_t encoded_sz, i;
    uint8_t *encoded_data, *optr;
    const uint8_t *iptr;

    encoded_sz = (sz / 3) * 4;
    if (sz % 3 != 0)
        encoded_sz += 4;

    encoded_data = c_malloc(encoded_sz);

    iptr = (const uint8_t *)data;
    optr = encoded_data;

    for (i = 0; i < sz - sz % 3; i += 3) {
        /* +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
         * |a|a|a|a|a|a|b|b| |b|b|b|b|c|c|c|c| |c|c|d|d|d|d|d|d|
         * +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+ */

        a = ((iptr[0] & 0xfc) >> 2);
        b = ((iptr[0] & 0x03) << 4) | ((iptr[1] & 0xf0) >> 4);
        c = ((iptr[1] & 0x0f) << 2) | ((iptr[2] & 0xc0) >> 6);
        d =  (iptr[2] & 0x3f);

        *optr++ = chars[a];
        *optr++ = chars[b];
        *optr++ = chars[c];
        *optr++ = chars[d];

        iptr += 3;
    }

    switch (sz % 3) {
    case 1:
        a = (iptr[0] & 0xfc) >> 2;
        b = (iptr[0] & 0x03) << 4;

        *optr++ = chars[a];
        *optr++ = chars[b];
        *optr++ = '=';
        *optr++ = '=';
        break;

    case 2:
        a = ((iptr[0] & 0xfc) >> 2);
        b = ((iptr[0] & 0x03) << 4) | ((iptr[1] & 0xf0) >> 4);
        c = ((iptr[1] & 0x0f) << 2);

        *optr++ = chars[a];
        *optr++ = chars[b];
        *optr++ = chars[c];
        *optr++ = '=';
        break;
    }

    if (pesz)
        *pesz = encoded_sz;
    return encoded_data;
}

char *
http_base64_decode_string(const char *string) {
    char *dstring;
    size_t dsz;

    dstring = (char *)http_base64_decode(string, strlen(string), &dsz);
    if (!dstring)
        return NULL;

    dstring = c_realloc(dstring, dsz + 1);
    dstring[dsz] = '\0';

    return dstring;
}

char *
http_base64_encode_string(const char *string) {
    char *estring;
    size_t esz;

    estring = (char *)http_base64_encode(string, strlen(string), &esz);
    if (!estring)
        return NULL;

    estring = c_realloc(estring, esz + 1);
    estring[esz] = '\0';

    return estring;
}
