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

void
http_format_date(char buf[static HTTP_RFC1123_DATE_BUFSZ], size_t sz,
                 const struct tm *tm) {
    strftime(buf, sz, "%a, %d %b %Y %H:%M:%S %z", tm);
}

int
http_format_timestamp(char buf[static HTTP_RFC1123_DATE_BUFSZ], size_t sz,
                      time_t timestamp) {
    struct tm *tm;

    tm = gmtime(&timestamp);
    if (!tm) {
        c_set_error("cannot get date from timestamp: %s", strerror(errno));
        return -1;
    }

    http_format_date(buf, sz, tm);
    return 0;
}
