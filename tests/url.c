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

#include "../src/internal.h"

TEST(base) {
    struct http_url *url;
    const char *value;

#define HTTPT_PARSE_URL(str_)                                  \
    do {                                                       \
        url = http_url_parse(str_);                            \
        if (!url)                                              \
            TEST_ABORT("cannot parse url: %s", c_get_error()); \
    } while (0)

    /* Scheme */
    HTTPT_PARSE_URL("a://");
    TEST_STRING_EQ(url->scheme, "a");
    http_url_delete(url);

    HTTPT_PARSE_URL("http://");
    TEST_STRING_EQ(url->scheme, "http");
    http_url_delete(url);

    HTTPT_PARSE_URL("a+bc-.ABC://");
    TEST_STRING_EQ(url->scheme, "a+bc-.ABC");
    http_url_delete(url);

    /* Host */
    HTTPT_PARSE_URL("//a");
    TEST_STRING_EQ(url->host, "a");
    http_url_delete(url);

    HTTPT_PARSE_URL("http://a");
    TEST_STRING_EQ(url->host, "a");
    http_url_delete(url);

    HTTPT_PARSE_URL("http://example.com");
    TEST_STRING_EQ(url->host, "example.com");
    http_url_delete(url);

    /* Port */
    HTTPT_PARSE_URL("//a:80");
    TEST_STRING_EQ(url->host, "a");
    TEST_STRING_EQ(url->port, "80");
    TEST_UINT_EQ(url->port_number, 80);
    http_url_delete(url);

    HTTPT_PARSE_URL("http://a:80");
    TEST_STRING_EQ(url->host, "a");
    TEST_STRING_EQ(url->port, "80");
    TEST_UINT_EQ(url->port_number, 80);
    http_url_delete(url);

    HTTPT_PARSE_URL("http://a:65535");
    TEST_STRING_EQ(url->host, "a");
    TEST_STRING_EQ(url->port, "65535");
    TEST_UINT_EQ(url->port_number, 65535);
    http_url_delete(url);

    HTTPT_PARSE_URL("http://a:80/");
    TEST_STRING_EQ(url->host, "a");
    TEST_STRING_EQ(url->port, "80");
    TEST_UINT_EQ(url->port_number, 80);
    http_url_delete(url);

    HTTPT_PARSE_URL("http://a:80?");
    TEST_STRING_EQ(url->host, "a");
    TEST_STRING_EQ(url->port, "80");
    TEST_UINT_EQ(url->port_number, 80);
    http_url_delete(url);

    HTTPT_PARSE_URL("http://a:80#");
    TEST_STRING_EQ(url->host, "a");
    TEST_STRING_EQ(url->port, "80");
    TEST_UINT_EQ(url->port_number, 80);
    http_url_delete(url);

    HTTPT_PARSE_URL("http://127.0.0.1");
    TEST_STRING_EQ(url->host, "127.0.0.1");
    http_url_delete(url);

    HTTPT_PARSE_URL("http://[fd14:a10:ca6c::1]");
    TEST_STRING_EQ(url->host, "fd14:a10:ca6c::1");
    http_url_delete(url);

    HTTPT_PARSE_URL("http://[fd14:a10:ca6c::1]:80");
    TEST_STRING_EQ(url->host, "fd14:a10:ca6c::1");
    TEST_STRING_EQ(url->port, "80");
    TEST_UINT_EQ(url->port_number, 80);
    http_url_delete(url);

    HTTPT_PARSE_URL("http://[fd14:a10:ca6c::1]/");
    TEST_STRING_EQ(url->host, "fd14:a10:ca6c::1");
    http_url_delete(url);

    /* User info */
    HTTPT_PARSE_URL("http://foo@a");
    TEST_STRING_EQ(url->host, "a");
    TEST_STRING_EQ(url->user, "foo");
    http_url_delete(url);

    HTTPT_PARSE_URL("http://foo:bar@a");
    TEST_STRING_EQ(url->host, "a");
    TEST_STRING_EQ(url->user, "foo");
    TEST_STRING_EQ(url->password, "bar");
    http_url_delete(url);

    HTTPT_PARSE_URL("http://foo:a%3ab%3ac@a");
    TEST_STRING_EQ(url->host, "a");
    TEST_STRING_EQ(url->user, "foo");
    TEST_STRING_EQ(url->password, "a:b:c");
    http_url_delete(url);

    HTTPT_PARSE_URL("http://%66o%6f:b%61r@a");
    TEST_STRING_EQ(url->host, "a");
    TEST_STRING_EQ(url->user, "foo");
    TEST_STRING_EQ(url->password, "bar");
    http_url_delete(url);

    /* TODO Path */

    /* Path only */
    HTTPT_PARSE_URL("/");
    TEST_STRING_EQ(url->path, "/");
    http_url_delete(url);

    HTTPT_PARSE_URL("/foo");
    TEST_STRING_EQ(url->path, "/foo");
    http_url_delete(url);

    HTTPT_PARSE_URL("/a/b/c");
    TEST_STRING_EQ(url->path, "/a/b/c");
    http_url_delete(url);

    /* Query */
    HTTPT_PARSE_URL("http://example.com?");
    TEST_STRING_EQ(url->query, "");
    http_url_delete(url);

    HTTPT_PARSE_URL("http://example.com?a");
    TEST_STRING_EQ(url->query, "a");
    TEST_BOOL_EQ(http_url_has_query_parameter(url, "a", &value), true);
    TEST_PTR_NULL(value);
    http_url_delete(url);

    HTTPT_PARSE_URL("http://example.com?a=1&b=2&foo=bar");
    TEST_STRING_EQ(url->query, "a=1&b=2&foo=bar");
    TEST_BOOL_EQ(http_url_has_query_parameter(url, "a", &value), true);
    TEST_STRING_EQ(value, "1");
    TEST_BOOL_EQ(http_url_has_query_parameter(url, "b", &value), true);
    TEST_STRING_EQ(value, "2");
    TEST_BOOL_EQ(http_url_has_query_parameter(url, "foo", &value), true);
    TEST_STRING_EQ(value, "bar");
    http_url_delete(url);

    HTTPT_PARSE_URL("http://example.com?:path@=/a/b/c&?=?");
    TEST_STRING_EQ(url->query, ":path@=/a/b/c&?=?");
    TEST_BOOL_EQ(http_url_has_query_parameter(url, ":path@", &value), true);
    TEST_STRING_EQ(value, "/a/b/c");
    TEST_BOOL_EQ(http_url_has_query_parameter(url, "?", &value), true);
    TEST_STRING_EQ(value, "?");
    http_url_delete(url);

    HTTPT_PARSE_URL("http://example.com?%3fabc;a=%20");
    TEST_STRING_EQ(url->query, "%3fabc;a=%20");
    TEST_BOOL_EQ(http_url_has_query_parameter(url, "?abc", &value), true);
    TEST_PTR_NULL(value);
    TEST_BOOL_EQ(http_url_has_query_parameter(url, "a", &value), true);
    TEST_STRING_EQ(value, " ");
    http_url_delete(url);

    /* Fragment */
    HTTPT_PARSE_URL("http://example.com#");
    TEST_STRING_EQ(url->fragment, "");
    http_url_delete(url);

    HTTPT_PARSE_URL("http://example.com#a");
    TEST_STRING_EQ(url->fragment, "a");
    http_url_delete(url);

    HTTPT_PARSE_URL("http://example.com#/foo?bar@:baz");
    TEST_STRING_EQ(url->fragment, "/foo?bar@:baz");
    http_url_delete(url);

    HTTPT_PARSE_URL("http://example.com#%23%20a%20");
    TEST_STRING_EQ(url->fragment, "# a ");
    http_url_delete(url);

    HTTPT_PARSE_URL("http://example.com?foo#bar");
    TEST_STRING_EQ(url->query, "foo");
    TEST_STRING_EQ(url->fragment, "bar");
    http_url_delete(url);

#undef HTTPT_PARSE_URL
}

TEST(invalid) {
#define HTTPT_INVALID_URL(str_)               \
    do {                                      \
        struct http_url *url;                 \
                                              \
        url = http_url_parse(str_);           \
        if (url)                              \
            TEST_ABORT("parsed invalid url"); \
    } while (0)

    /* Scheme */
    HTTPT_INVALID_URL("2a://");
    HTTPT_INVALID_URL("://");
    HTTPT_INVALID_URL("\\://");

    /* TODO Host */

    /* Port */
    HTTPT_INVALID_URL("http://a:");
    HTTPT_INVALID_URL("http://a:a80");
    HTTPT_INVALID_URL("http://a:80a");
    HTTPT_INVALID_URL("http://a:0");
    HTTPT_INVALID_URL("http://a:100000");

    /* TODO User info */

    /* TODO Path */

    /* TODO Path only */

    /* TODO Query */

    /* TODO Fragment */

#undef HTTPT_INVALID_URL
}

int
main(int argc, char **argv) {
    struct test_suite *suite;

    suite = test_suite_new("url");
    test_suite_initialize_from_args(suite, argc, argv);

    test_suite_start(suite);

    TEST_RUN(suite, base);
    TEST_RUN(suite, invalid);

    test_suite_print_results_and_exit(suite);
}
