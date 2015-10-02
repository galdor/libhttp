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

TEST(media_types) {
    struct http_media_type *media_type;

#define HTTPT_MIME_MEDIA_TYPE_PARSE(str_)                                  \
    do {                                                                   \
        media_type = http_media_type_parse(str_);                          \
        if (!media_type)                                                   \
            TEST_ABORT("cannot parse mime media type: %s", c_get_error()); \
    } while (0)

#define HTTPT_MIME_MEDIA_TYPE_PARAMETER_IS(name_, value_)                  \
    do {                                                                   \
        TEST_STRING_EQ(http_media_type_parameter(media_type, name_),       \
                       value_);                                            \
    } while (0)

    HTTPT_MIME_MEDIA_TYPE_PARSE("text/plain");
    TEST_STRING_EQ(http_media_type_string(media_type), "text/plain");
    TEST_STRING_EQ(http_media_type_base_string(media_type),
                   "text/plain");
    TEST_STRING_EQ(http_media_type_type(media_type), "text");
    TEST_STRING_EQ(http_media_type_subtype(media_type), "plain");
    http_media_type_delete(media_type);

    HTTPT_MIME_MEDIA_TYPE_PARSE("Text/PLAIn");
    TEST_STRING_EQ(http_media_type_string(media_type), "text/plain");
    TEST_STRING_EQ(http_media_type_base_string(media_type),
                   "text/plain");
    TEST_STRING_EQ(http_media_type_type(media_type), "text");
    TEST_STRING_EQ(http_media_type_subtype(media_type), "plain");
    http_media_type_delete(media_type);

    HTTPT_MIME_MEDIA_TYPE_PARSE("text/plain; charset=UTF-8");
    TEST_STRING_EQ(http_media_type_string(media_type),
                   "text/plain; charset=UTF-8");
    TEST_STRING_EQ(http_media_type_base_string(media_type), "text/plain");
    TEST_STRING_EQ(http_media_type_type(media_type), "text");
    TEST_STRING_EQ(http_media_type_subtype(media_type), "plain");
    HTTPT_MIME_MEDIA_TYPE_PARAMETER_IS("charset", "UTF-8");
    http_media_type_delete(media_type);

    HTTPT_MIME_MEDIA_TYPE_PARSE("text/plain ;CHarsET=UTF-8");
    TEST_STRING_EQ(http_media_type_string(media_type),
                   "text/plain; charset=UTF-8");
    TEST_STRING_EQ(http_media_type_base_string(media_type), "text/plain");
    TEST_STRING_EQ(http_media_type_type(media_type), "text");
    TEST_STRING_EQ(http_media_type_subtype(media_type), "plain");
    HTTPT_MIME_MEDIA_TYPE_PARAMETER_IS("charset", "UTF-8");
    http_media_type_delete(media_type);

    HTTPT_MIME_MEDIA_TYPE_PARSE("text/plain;a=1; b=2  ;c=3   ;  d=4");
    TEST_STRING_EQ(http_media_type_string(media_type),
                   "text/plain; a=1; d=4; c=3; b=2");
    TEST_STRING_EQ(http_media_type_base_string(media_type),
                   "text/plain");
    TEST_STRING_EQ(http_media_type_type(media_type), "text");
    TEST_STRING_EQ(http_media_type_subtype(media_type), "plain");
    HTTPT_MIME_MEDIA_TYPE_PARAMETER_IS("a", "1");
    HTTPT_MIME_MEDIA_TYPE_PARAMETER_IS("b", "2");
    HTTPT_MIME_MEDIA_TYPE_PARAMETER_IS("c", "3");
    HTTPT_MIME_MEDIA_TYPE_PARAMETER_IS("d", "4");
    http_media_type_delete(media_type);

    HTTPT_MIME_MEDIA_TYPE_PARSE("text/plain; a=foo; b=\"foo\"; c=\"\\\"foo\\\"\"");
    TEST_STRING_EQ(http_media_type_string(media_type),
                   "text/plain; a=foo; c=\"\\\"foo\\\"\"; b=foo");
    TEST_STRING_EQ(http_media_type_base_string(media_type), "text/plain");
    TEST_STRING_EQ(http_media_type_type(media_type), "text");
    TEST_STRING_EQ(http_media_type_subtype(media_type), "plain");
    HTTPT_MIME_MEDIA_TYPE_PARAMETER_IS("a", "foo");
    HTTPT_MIME_MEDIA_TYPE_PARAMETER_IS("b", "foo");
    HTTPT_MIME_MEDIA_TYPE_PARAMETER_IS("c", "\"foo\"");
    http_media_type_delete(media_type);
}

TEST(invalid_media_types) {
#define HTTPT_INVALID_MIME_MEDIA_TYPE(str_)               \
    do {                                                  \
        struct http_media_type *media_type;               \
                                                          \
        media_type = http_media_type_parse(str_);         \
        if (media_type)                                   \
            TEST_ABORT("parsed invalid mime media type"); \
    } while (0)

    /* Invalid type */
    HTTPT_INVALID_MIME_MEDIA_TYPE("");
    HTTPT_INVALID_MIME_MEDIA_TYPE("/plain");
    HTTPT_INVALID_MIME_MEDIA_TYPE("tex!");

    /* Invalid subtype */
    HTTPT_INVALID_MIME_MEDIA_TYPE("text/");
    HTTPT_INVALID_MIME_MEDIA_TYPE("text/ plain");

    /* Invalid parameters */
    HTTPT_INVALID_MIME_MEDIA_TYPE("text/plain;");
    HTTPT_INVALID_MIME_MEDIA_TYPE("text/plain; name");
    HTTPT_INVALID_MIME_MEDIA_TYPE("text/plain; name=");
    HTTPT_INVALID_MIME_MEDIA_TYPE("text/plain; name;");
    HTTPT_INVALID_MIME_MEDIA_TYPE("text/plain; a=\";");
    HTTPT_INVALID_MIME_MEDIA_TYPE("text/plain; a=\";");
    HTTPT_INVALID_MIME_MEDIA_TYPE("text/plain; a=\"\\\"");
    HTTPT_INVALID_MIME_MEDIA_TYPE("text/plain; a=\"\\x\"");
    HTTPT_INVALID_MIME_MEDIA_TYPE("text/plain; a=\"foo\";");
}

int
main(int argc, char **argv) {
    struct test_suite *suite;

    suite = test_suite_new("mime");
    test_suite_initialize_from_args(suite, argc, argv);

    test_suite_start(suite);

    TEST_RUN(suite, media_types);
    TEST_RUN(suite, invalid_media_types);

    test_suite_print_results_and_exit(suite);
}
