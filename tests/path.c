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
    struct http_path *path;

#define HTTPT_PARSE_PATH(str_)                                  \
    do {                                                        \
        path = http_path_parse(str_);                           \
        if (!path)                                              \
            TEST_ABORT("cannot parse path: %s", c_get_error()); \
    } while (0)

    HTTPT_PARSE_PATH("/");
    TEST_UINT_EQ(http_path_nb_segments(path), 0);
    http_path_delete(path);

    HTTPT_PARSE_PATH("/foo");
    TEST_UINT_EQ(http_path_nb_segments(path), 1);
    TEST_STRING_EQ(http_path_segment(path, 0), "foo");
    http_path_delete(path);

    HTTPT_PARSE_PATH("/foo/");
    TEST_UINT_EQ(http_path_nb_segments(path), 1);
    TEST_STRING_EQ(http_path_segment(path, 0), "foo");
    http_path_delete(path);

    HTTPT_PARSE_PATH("/a/b/c");
    TEST_UINT_EQ(http_path_nb_segments(path), 3);
    TEST_STRING_EQ(http_path_segment(path, 0), "a");
    TEST_STRING_EQ(http_path_segment(path, 1), "b");
    TEST_STRING_EQ(http_path_segment(path, 2), "c");
    http_path_delete(path);

    HTTPT_PARSE_PATH("/a/b/c/");
    TEST_UINT_EQ(http_path_nb_segments(path), 3);
    TEST_STRING_EQ(http_path_segment(path, 0), "a");
    TEST_STRING_EQ(http_path_segment(path, 1), "b");
    TEST_STRING_EQ(http_path_segment(path, 2), "c");
    http_path_delete(path);

#undef HTTPT_PARSE_PATH
}

TEST(invalid) {
#define HTTPT_INVALID_PATH(str_)               \
    do {                                       \
        struct http_path *path;                \
                                               \
        path = http_path_parse(str_);          \
        if (path)                              \
            TEST_ABORT("parsed invalid path"); \
    } while (0)

    HTTPT_INVALID_PATH("");
    HTTPT_INVALID_PATH("foo");
    HTTPT_INVALID_PATH("/a//");
    HTTPT_INVALID_PATH("/a//b");

#undef HTTPT_INVALID_PATH
}

int
main(int argc, char **argv) {
    struct test_suite *suite;

    suite = test_suite_new("path");
    test_suite_initialize_from_args(suite, argc, argv);

    test_suite_start(suite);

    TEST_RUN(suite, base);
    TEST_RUN(suite, invalid);

    test_suite_print_results_and_exit(suite);
}
