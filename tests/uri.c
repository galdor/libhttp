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
    struct http_uri *uri;
    const char *value;

#define HTTPT_PARSE_URI(str_)                                  \
    do {                                                       \
        uri = http_uri_parse(str_);                            \
        if (!uri)                                              \
            TEST_ABORT("cannot parse uri: %s", c_get_error()); \
    } while (0)

    /* Scheme */
    HTTPT_PARSE_URI("a://");
    TEST_STRING_EQ(uri->scheme, "a");
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://");
    TEST_STRING_EQ(uri->scheme, "http");
    http_uri_delete(uri);

    HTTPT_PARSE_URI("a+bc-.ABC://");
    TEST_STRING_EQ(uri->scheme, "a+bc-.ABC");
    http_uri_delete(uri);

    /* Host */
    HTTPT_PARSE_URI("http://a");
    TEST_STRING_EQ(uri->host, "a");
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://example.com");
    TEST_STRING_EQ(uri->host, "example.com");
    http_uri_delete(uri);

    /* Port */
    HTTPT_PARSE_URI("http://a:80");
    TEST_STRING_EQ(uri->host, "a");
    TEST_STRING_EQ(uri->port, "80");
    TEST_UINT_EQ(uri->port_number, 80);
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://a:65535");
    TEST_STRING_EQ(uri->host, "a");
    TEST_STRING_EQ(uri->port, "65535");
    TEST_UINT_EQ(uri->port_number, 65535);
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://a:80/");
    TEST_STRING_EQ(uri->host, "a");
    TEST_STRING_EQ(uri->port, "80");
    TEST_UINT_EQ(uri->port_number, 80);
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://a:80?");
    TEST_STRING_EQ(uri->host, "a");
    TEST_STRING_EQ(uri->port, "80");
    TEST_UINT_EQ(uri->port_number, 80);
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://a:80#");
    TEST_STRING_EQ(uri->host, "a");
    TEST_STRING_EQ(uri->port, "80");
    TEST_UINT_EQ(uri->port_number, 80);
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://127.0.0.1");
    TEST_STRING_EQ(uri->host, "127.0.0.1");
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://[fd14:a10:ca6c::1]");
    TEST_STRING_EQ(uri->host, "fd14:a10:ca6c::1");
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://[fd14:a10:ca6c::1]:80");
    TEST_STRING_EQ(uri->host, "fd14:a10:ca6c::1");
    TEST_STRING_EQ(uri->port, "80");
    TEST_UINT_EQ(uri->port_number, 80);
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://[fd14:a10:ca6c::1]/");
    TEST_STRING_EQ(uri->host, "fd14:a10:ca6c::1");
    http_uri_delete(uri);

    /* User info */
    HTTPT_PARSE_URI("http://foo@a");
    TEST_STRING_EQ(uri->host, "a");
    TEST_STRING_EQ(uri->user, "foo");
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://foo:bar@a");
    TEST_STRING_EQ(uri->host, "a");
    TEST_STRING_EQ(uri->user, "foo");
    TEST_STRING_EQ(uri->password, "bar");
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://foo:a%3ab%3ac@a");
    TEST_STRING_EQ(uri->host, "a");
    TEST_STRING_EQ(uri->user, "foo");
    TEST_STRING_EQ(uri->password, "a:b:c");
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://%66o%6f:b%61r@a");
    TEST_STRING_EQ(uri->host, "a");
    TEST_STRING_EQ(uri->user, "foo");
    TEST_STRING_EQ(uri->password, "bar");
    http_uri_delete(uri);

    /* TODO Path */

    /* Path only */
    HTTPT_PARSE_URI("/");
    TEST_STRING_EQ(uri->path, "/");
    http_uri_delete(uri);

    HTTPT_PARSE_URI("/foo");
    TEST_STRING_EQ(uri->path, "/foo");
    http_uri_delete(uri);

    HTTPT_PARSE_URI("/a/b/c");
    TEST_STRING_EQ(uri->path, "/a/b/c");
    http_uri_delete(uri);

    /* Query */
    HTTPT_PARSE_URI("http://example.com?");
    TEST_STRING_EQ(uri->query, "");
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://example.com?a");
    TEST_STRING_EQ(uri->query, "a");
    TEST_BOOL_EQ(http_uri_has_query_parameter(uri, "a", &value), true);
    TEST_PTR_NULL(value);
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://example.com?a=1&b=2&foo=bar");
    TEST_STRING_EQ(uri->query, "a=1&b=2&foo=bar");
    TEST_BOOL_EQ(http_uri_has_query_parameter(uri, "a", &value), true);
    TEST_STRING_EQ(value, "1");
    TEST_BOOL_EQ(http_uri_has_query_parameter(uri, "b", &value), true);
    TEST_STRING_EQ(value, "2");
    TEST_BOOL_EQ(http_uri_has_query_parameter(uri, "foo", &value), true);
    TEST_STRING_EQ(value, "bar");
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://example.com?:path@=/a/b/c&?=?");
    TEST_STRING_EQ(uri->query, ":path@=/a/b/c&?=?");
    TEST_BOOL_EQ(http_uri_has_query_parameter(uri, ":path@", &value), true);
    TEST_STRING_EQ(value, "/a/b/c");
    TEST_BOOL_EQ(http_uri_has_query_parameter(uri, "?", &value), true);
    TEST_STRING_EQ(value, "?");
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://example.com?%3fabc;a=%20");
    TEST_STRING_EQ(uri->query, "%3fabc;a=%20");
    TEST_BOOL_EQ(http_uri_has_query_parameter(uri, "?abc", &value), true);
    TEST_PTR_NULL(value);
    TEST_BOOL_EQ(http_uri_has_query_parameter(uri, "a", &value), true);
    TEST_STRING_EQ(value, " ");
    http_uri_delete(uri);

    /* Fragment */
    HTTPT_PARSE_URI("http://example.com#");
    TEST_STRING_EQ(uri->fragment, "");
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://example.com#a");
    TEST_STRING_EQ(uri->fragment, "a");
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://example.com#/foo?bar@:baz");
    TEST_STRING_EQ(uri->fragment, "/foo?bar@:baz");
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://example.com#%23%20a%20");
    TEST_STRING_EQ(uri->fragment, "# a ");
    http_uri_delete(uri);

    HTTPT_PARSE_URI("http://example.com?foo#bar");
    TEST_STRING_EQ(uri->query, "foo");
    TEST_STRING_EQ(uri->fragment, "bar");
    http_uri_delete(uri);

#undef HTTPT_PARSE_URI
}

TEST(invalid) {
#define HTTPT_INVALID_URI(str_)               \
    do {                                      \
        struct http_uri *uri;                 \
                                              \
        uri = http_uri_parse(str_);           \
        if (uri)                              \
            TEST_ABORT("parsed invalid uri"); \
    } while (0)

    /* Scheme */
    HTTPT_INVALID_URI("2a://");
    HTTPT_INVALID_URI("://");
    HTTPT_INVALID_URI("\\://");

    /* TODO Host */

    /* Port */
    HTTPT_INVALID_URI("http://a:");
    HTTPT_INVALID_URI("http://a:a80");
    HTTPT_INVALID_URI("http://a:80a");
    HTTPT_INVALID_URI("http://a:0");
    HTTPT_INVALID_URI("http://a:100000");

    /* TODO User info */

    /* TODO Path */

    /* TODO Path only */

    /* TODO Query */

    /* TODO Fragment */

#undef HTTPT_INVALID_URI
}

int
main(int argc, char **argv) {
    struct test_suite *suite;

    suite = test_suite_new("uri");
    test_suite_initialize_from_args(suite, argc, argv);

    test_suite_start(suite);

    TEST_RUN(suite, base);
    TEST_RUN(suite, invalid);

    test_suite_print_results_and_exit(suite);
}
