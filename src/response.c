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

struct http_response *
http_response_new(enum http_status status) {
    struct http_response *response;

    response = c_malloc0(sizeof(struct http_response));

    response->version = HTTP_1_1;
    response->status = status;
    response->headers = http_headers_new();

    return response;
}

void
http_response_delete(struct http_response *response) {
    if (!response)
        return;

    http_headers_delete(response->headers);

    c_free(response->body);

    c_free0(response, sizeof(struct http_response));
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
    c_buffer_add(buf, response->body, response->body_sz);
}

void
http_response_add_header(struct http_response *response,
                        const char *name, const char *value) {
    http_headers_add(response->headers, name, value);
}

void
http_response_add_header_nocopy(struct http_response *response,
                               char *name, char *value) {
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
