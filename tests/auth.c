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

TEST(basic) {
#define HTTPT_AUTH(string_, user_, password_)                            \
    do {                                                                 \
        struct http_auth *auth;                                          \
                                                                         \
        auth = http_auth_parse_authorization(string_);                   \
        if (!auth)                                                       \
            TEST_ABORT("cannot parse authorization: %s", c_get_error()); \
                                                                         \
        TEST_INT_EQ(auth->scheme, HTTP_AUTH_SCHEME_BASIC);               \
        TEST_STRING_EQ(auth->u.basic.user, user_);                       \
        TEST_STRING_EQ(auth->u.basic.password, password_);               \
                                                                         \
        http_auth_delete(auth);                                          \
    } while (0)

    HTTPT_AUTH("Basic YTpi", "a", "b");
    HTTPT_AUTH("Basic  Zm9vOmI=\t", "foo", "b");
    HTTPT_AUTH("Basic\tYTpiYXI= ", "a", "bar");
    HTTPT_AUTH("Basic\t \tZm9vOmJhcg==  ", "foo", "bar");
    HTTPT_AUTH("Basic\t\t  Zm9vIGJhcjphIGIgYw==\t\t", "foo bar", "a b c");
    HTTPT_AUTH("Basic \t IGEgYiBjICA6IGQgZSBmIA==", " a b c  ", " d e f ");

#undef HTTPT_AUTH
}

TEST(invalid) {
#define HTTPT_AUTH_INVALID(string_)                                      \
    do {                                                                 \
        struct http_auth *auth;                                          \
                                                                         \
        auth = http_auth_parse_authorization(string_);                   \
        if (auth)                                                        \
            TEST_ABORT("parsed invalid authorization");                  \
    } while (0)

    HTTPT_AUTH_INVALID("");
    HTTPT_AUTH_INVALID("foo");
    HTTPT_AUTH_INVALID("foo bar");

    HTTPT_AUTH_INVALID("Basic ");
    HTTPT_AUTH_INVALID("Basic IA==");     /* " " */
    HTTPT_AUTH_INVALID("Basic Zm9v");     /* "foo" */
    HTTPT_AUTH_INVALID("Basic Og==");     /* ":" */
    HTTPT_AUTH_INVALID("Basic OmJhcg=="); /* ":bar" */

#undef HTTPT_AUTH_INVALID
}

int
main(int argc, char **argv) {
    struct test_suite *suite;

    suite = test_suite_new("auth");
    test_suite_initialize_from_args(suite, argc, argv);

    test_suite_start(suite);

    TEST_RUN(suite, basic);
    TEST_RUN(suite, invalid);

    test_suite_print_results_and_exit(suite);
}

