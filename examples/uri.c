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

#include <signal.h>

#include "http.h"

static void httpex_die(const char *, ...)
    __attribute__ ((format(printf, 1, 2), noreturn));

int
main(int argc, char **argv) {
    struct c_command_line *cmdline;
    const char *uri_string;
    struct http_uri *uri;
    char *result;

    cmdline = c_command_line_new();

    c_command_line_add_argument(cmdline, "the uri string", "uri");

    if (c_command_line_parse(cmdline, argc, argv) == -1)
        httpex_die("%s", c_get_error());

    uri_string = c_command_line_argument_value(cmdline, 0);

    uri = http_uri_parse(uri_string);
    if (!uri)
        httpex_die("cannot parse uri: %s", c_get_error());

    if (http_uri_scheme(uri))
        printf("- %-12s  '%s'\n", "scheme", http_uri_scheme(uri));
    if (http_uri_user(uri))
        printf("- %-12s  '%s'\n", "user", http_uri_user(uri));
    if (http_uri_password(uri))
        printf("- %-12s  '%s'\n", "password", http_uri_password(uri));
    if (http_uri_host(uri))
        printf("- %-12s  '%s'\n", "host", http_uri_host(uri));
    if (http_uri_port(uri)) {
        printf("- %-12s  '%s'\n", "port", http_uri_port(uri));
        printf("  %-12s  %u\n", "port number", http_uri_port_number(uri));
    }
    if (http_uri_path(uri))
        printf("- %-12s  '%s'\n", "path", http_uri_path(uri));
    if (http_uri_query(uri))
        printf("- %-12s  '%s'\n", "query", http_uri_query(uri));
    if (http_uri_fragment(uri))
        printf("- %-12s  '%s'\n", "fragment", http_uri_fragment(uri));

    result = http_uri_to_string(uri);
    printf("\n%s\n", result);
    c_free(result);

    http_uri_delete(uri);

    c_command_line_delete(cmdline);
    return 0;
}

void
httpex_die(const char *fmt, ...) {
    va_list ap;

    fprintf(stderr, "fatal error: ");

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    putc('\n', stderr);
    exit(1);
}
