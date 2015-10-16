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

#include "../src/http.h"

static void httpex_die(const char *, ...)
    __attribute__ ((format(printf, 1, 2), noreturn));

int
main(int argc, char **argv) {
    struct c_command_line *cmdline;
    const char *url_string;
    struct http_url *url;
    char *result;

    cmdline = c_command_line_new();

    c_command_line_add_argument(cmdline, "the url string", "url");

    if (c_command_line_parse(cmdline, argc, argv) == -1)
        httpex_die("%s", c_get_error());

    url_string = c_command_line_argument_value(cmdline, 0);

    url = http_url_parse(url_string);
    if (!url)
        httpex_die("cannot parse url: %s", c_get_error());

    if (http_url_scheme(url))
        printf("- %-12s  '%s'\n", "scheme", http_url_scheme(url));
    if (http_url_user(url))
        printf("- %-12s  '%s'\n", "user", http_url_user(url));
    if (http_url_password(url))
        printf("- %-12s  '%s'\n", "password", http_url_password(url));
    if (http_url_host(url))
        printf("- %-12s  '%s'\n", "host", http_url_host(url));
    if (http_url_port(url)) {
        printf("- %-12s  '%s'\n", "port", http_url_port(url));
        printf("  %-12s  %u\n", "port number", http_url_port_number(url));
    }
    if (http_url_path(url))
        printf("- %-12s  '%s'\n", "path", http_url_path(url));
    if (http_url_query(url)) {
        size_t nb_params;

        printf("- %-12s  '%s'\n", "query", http_url_query(url));

        nb_params = http_url_nb_query_parameters(url);
        for (size_t i = 0; i < nb_params; i++) {
            const char *name, *value;

            name = http_url_nth_query_parameter(url, i, &value);

            if (value) {
                printf("  %-12s  %s\n", name, value);
            } else {
                printf("  %-12s\n", name);
            }
        }
    }
    if (http_url_fragment(url))
        printf("- %-12s  '%s'\n", "fragment", http_url_fragment(url));

    result = http_url_to_string(url);
    printf("\n%s\n", result);
    c_free(result);

    http_url_delete(url);

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
