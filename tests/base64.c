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

TEST(base64_decode) {
#define HTTPT_BASE64_DECODE(string_, result_)                               \
    do {                                                                    \
        char *result;                                                       \
                                                                            \
        result = http_base64_decode_string(string_);                        \
        if (!result)                                                        \
            TEST_ABORT("cannot decode base64: %s", c_get_error());          \
        TEST_STRING_EQ(result, result_);                                    \
                                                                            \
        c_free(result);                                                     \
    } while (0)

    HTTPT_BASE64_DECODE("", "");
    HTTPT_BASE64_DECODE("Zg==", "f");
    HTTPT_BASE64_DECODE("Zm8=", "fo");
    HTTPT_BASE64_DECODE("Zm9v", "foo");
    HTTPT_BASE64_DECODE("Zm9vYg==", "foob");
    HTTPT_BASE64_DECODE("Zm9vYmE=", "fooba");
    HTTPT_BASE64_DECODE("Zm9vYmFy", "foobar");

#undef HTTPT_BASE64_DECODE


#define HTTPT_BASE64_INVALID(string_)                                        \
    do {                                                                     \
        char *result;                                                        \
                                                                             \
        result = http_base64_decode_string(string_);                         \
        if (result)                                                          \
            TEST_ABORT("decoded invalid base64");                            \
    } while (0)

    HTTPT_BASE64_INVALID("a");
    HTTPT_BASE64_INVALID("ab");
    HTTPT_BASE64_INVALID("abc");

    HTTPT_BASE64_INVALID("abc=a");
    HTTPT_BASE64_INVALID("abc=ab");
    HTTPT_BASE64_INVALID("abc=abc");
    HTTPT_BASE64_INVALID("abc=abcd");

    HTTPT_BASE64_INVALID("ab==a");
    HTTPT_BASE64_INVALID("ab==ab");
    HTTPT_BASE64_INVALID("ab==abc");
    HTTPT_BASE64_INVALID("ab==abcd");

    HTTPT_BASE64_INVALID("ab=d");
    HTTPT_BASE64_INVALID("a=cd");
    HTTPT_BASE64_INVALID("=bcd");

#undef HTTPT_BASE64_INVALID
}

TEST(base64_encode) {
#define HTTPT_BASE64_ENCODE(string_, result_)                               \
    do {                                                                    \
        char *result;                                                       \
                                                                            \
        result = http_base64_encode_string(string_);                        \
        TEST_STRING_EQ(result, result_);                                    \
                                                                            \
        c_free(result);                                                     \
    } while (0)

    HTTPT_BASE64_ENCODE("", "");
    HTTPT_BASE64_ENCODE("f", "Zg==");
    HTTPT_BASE64_ENCODE("fo", "Zm8=");
    HTTPT_BASE64_ENCODE("foo", "Zm9v");
    HTTPT_BASE64_ENCODE("foob", "Zm9vYg==");
    HTTPT_BASE64_ENCODE("fooba", "Zm9vYmE=");
    HTTPT_BASE64_ENCODE("foobar", "Zm9vYmFy");

#undef HTTPT_BASE64_ENCODE
}

int
main(int argc, char **argv) {
    struct test_suite *suite;

    suite = test_suite_new("base64");
    test_suite_initialize_from_args(suite, argc, argv);

    test_suite_start(suite);

    TEST_RUN(suite, base64_decode);
    TEST_RUN(suite, base64_encode);

    test_suite_print_results_and_exit(suite);
}

