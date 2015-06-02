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

TEST(memspn) {
    TEST_UINT_EQ(http_memspn("", 0, ""), 0);
    TEST_UINT_EQ(http_memspn("foo", 3, ""), 0);
    TEST_UINT_EQ(http_memspn("foo", 3, "fo"), 3);
    TEST_UINT_EQ(http_memspn("foobar", 6, "fo"), 3);
}

TEST(memcspn) {
    TEST_UINT_EQ(http_memcspn("", 0, ""), 0);
    TEST_UINT_EQ(http_memcspn("foo", 3, ""), 3);
    TEST_UINT_EQ(http_memcspn("foo", 3, "abc"), 3);
    TEST_UINT_EQ(http_memcspn("foobar", 3, "abc"), 3);
}

int
main(int argc, char **argv) {
    struct test_suite *suite;

    suite = test_suite_new("strings");
    test_suite_initialize_from_args(suite, argc, argv);

    test_suite_start(suite);

    TEST_RUN(suite, memspn);
    TEST_RUN(suite, memcspn);

    test_suite_print_results_and_exit(suite);
}
