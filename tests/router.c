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

#include <utest.h>

#include "internal.h"

TEST(base) {
    struct http_router *router;

#define HTTP_ROUTE_FOUND(path_, method_, cb_)                            \
    do {                                                                 \
        const struct http_route *route;                                  \
        enum http_status status;                                         \
        struct http_path *path;                                          \
                                                                         \
        path = http_path_parse(path_);                                   \
        if (!path)                                                       \
            TEST_ABORT("cannot parse path: %s", c_get_error());          \
                                                                         \
        route = http_router_find_route(router, method_, path, &status);  \
        if (!route) {                                                    \
            TEST_ABORT("cannot find route (%d %s)",                      \
                       status, http_status_to_string(status));           \
        }                                                                \
                                                                         \
        TEST_PTR_EQ((void *)(cb_), route->cb);                           \
                                                                         \
        http_path_delete(path);                                          \
    } while (0)

#define HTTP_ROUTE_NOT_FOUND(path_, method_, status_)                    \
    do {                                                                 \
        const struct http_route *route;                                  \
        enum http_status status;                                         \
        struct http_path *path;                                          \
                                                                         \
        path = http_path_parse(path_);                                   \
        if (!path)                                                       \
            TEST_ABORT("cannot parse path: %s", c_get_error());          \
                                                                         \
        route = http_router_find_route(router, method_, path, &status);  \
        if (route)                                                       \
            TEST_ABORT("found route %d", (int)route->cb);                \
                                                                         \
        TEST_INT_EQ(status, status_);                                    \
                                                                         \
        http_path_delete(path);                                          \
    } while (0)

    /* Simple routes */
    router = http_router_new();
    http_router_bind(router, "/",      HTTP_GET, (void *)1, NULL);
    http_router_bind(router, "/a",     HTTP_GET, (void *)2, NULL);
    http_router_bind(router, "/a/b/c", HTTP_GET, (void *)3, NULL);
    http_router_bind(router, "/b",     HTTP_GET, (void *)4, NULL);
    http_router_bind(router, "/b",     HTTP_PUT, (void *)5, NULL);

    HTTP_ROUTE_FOUND("/",      HTTP_GET, 1);
    HTTP_ROUTE_FOUND("/a",     HTTP_GET, 2);
    HTTP_ROUTE_FOUND("/a/b/c", HTTP_GET, 3);
    HTTP_ROUTE_FOUND("/b",     HTTP_GET, 4);
    HTTP_ROUTE_FOUND("/b",     HTTP_PUT, 5);

    HTTP_ROUTE_NOT_FOUND("/c", HTTP_GET, HTTP_404_NOT_FOUND);
    HTTP_ROUTE_NOT_FOUND("/",  HTTP_PUT, HTTP_405_METHOD_NOT_ALLOWED);
    HTTP_ROUTE_NOT_FOUND("/b", HTTP_HEAD, HTTP_405_METHOD_NOT_ALLOWED);

    http_router_delete(router);

    /* Wildcards */
    router = http_router_new();
    http_router_bind(router, "/a",     HTTP_GET, (void *)1, NULL);
    http_router_bind(router, "/b/?",   HTTP_GET, (void *)2, NULL);
    http_router_bind(router, "/b/?/y", HTTP_GET, (void *)3, NULL);

    HTTP_ROUTE_FOUND("/a",     HTTP_GET, 1);
    HTTP_ROUTE_FOUND("/b/x",   HTTP_GET, 2);
    HTTP_ROUTE_FOUND("/b/x/y", HTTP_GET, 3);

    HTTP_ROUTE_NOT_FOUND("/a/x",     HTTP_GET, HTTP_404_NOT_FOUND);
    HTTP_ROUTE_NOT_FOUND("/b/x",     HTTP_PUT, HTTP_405_METHOD_NOT_ALLOWED);
    HTTP_ROUTE_NOT_FOUND("/b/x/x",   HTTP_GET, HTTP_404_NOT_FOUND);
    HTTP_ROUTE_NOT_FOUND("/b/x/x/y", HTTP_GET, HTTP_404_NOT_FOUND);

    http_router_delete(router);
}

int
main(int argc, char **argv) {
    struct test_suite *suite;

    suite = test_suite_new("router");
    test_suite_initialize_from_args(suite, argc, argv);

    test_suite_start(suite);

    TEST_RUN(suite, base);

    test_suite_print_results_and_exit(suite);
}
