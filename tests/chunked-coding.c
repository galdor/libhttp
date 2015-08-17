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

TEST(main) {
#define HTTPT_CHUNKED_CODING(string_, body_sz_, body_)                   \
    do {                                                                 \
        char *body;                                                      \
        size_t body_sz;                                                  \
        size_t data_sz;                                                  \
        int ret;                                                         \
                                                                         \
        ret = http_chunked_data_parse(string_, strlen(string_),          \
                                      (void **)&body, &body_sz,          \
                                      &data_sz);                         \
        if (ret == -1)                                                   \
            TEST_ABORT("cannot parse chunked data: %s", c_get_error());  \
        if (ret == 0)                                                    \
            TEST_ABORT("truncated chunked data");                        \
                                                                         \
        TEST_UINT_EQ(body_sz, body_sz_);                                 \
        TEST_STRING_EQ(body, body_);                                     \
                                                                         \
        c_free(body);                                                    \
    } while (0)

    HTTPT_CHUNKED_CODING("0\r\n\r\n",
                         0, "");
    HTTPT_CHUNKED_CODING("3\r\nfoo\r\n6\r\nfoobar\r\n0\r\n\r\n",
                         9, "foofoobar");
    HTTPT_CHUNKED_CODING("a\r\nfoobar baz\r\n0\r\n\r\n",
                         10, "foobar baz");
    HTTPT_CHUNKED_CODING("1;a=1\r\na\r\n1 ; a=1\r\nb\r\n0\r\n\r\n",
                         2, "ab");
    HTTPT_CHUNKED_CODING("1;a=\"foo\"\r\na\r\n1 ; a=\"\"\r\nb\r\n0\r\n\r\n",
                         2, "ab");

#undef HTTPT_CHUNKED_CODING
}

int
main(int argc, char **argv) {
    struct test_suite *suite;

    suite = test_suite_new("chunked-coding");
    test_suite_initialize_from_args(suite, argc, argv);

    test_suite_start(suite);

    TEST_RUN(suite, main);

    test_suite_print_results_and_exit(suite);
}

