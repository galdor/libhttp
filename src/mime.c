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

#include "internal.h"

static void http_media_type_update_strings(struct http_media_type *);

static void http_media_type_parameter_to_buffer(const char *, struct c_buffer *);
static char *http_media_type_parameter_unescape(const char *, size_t);

struct http_media_type *
http_media_type_new(const char *type, const char *subtype) {
    struct http_media_type *media_type;

    media_type = c_malloc0(sizeof(struct http_media_type));

    media_type->type = c_strdup(type);
    media_type->subtype = c_strdup(subtype);

    media_type->parameters = c_hash_table_new(c_hash_string, c_equal_string);

    http_media_type_update_strings(media_type);

    return media_type;
}

void
http_media_type_delete(struct http_media_type *media_type) {
    struct c_hash_table_iterator *it;
    char *name, *value;

    if (!media_type)
        return;

    c_free(media_type->string);
    c_free(media_type->base_string);

    c_free(media_type->type);
    c_free(media_type->subtype);

    it = c_hash_table_iterate(media_type->parameters);
    while (c_hash_table_iterator_next(it, (void **)&name,
                                      (void **)&value) == 1) {
        c_free(name);
        c_free(value);
    }
    c_hash_table_iterator_delete(it);
    c_hash_table_delete(media_type->parameters);

    c_free0(media_type, sizeof(struct http_media_type));
}

struct http_media_type *
http_media_type_parse(const char *string) {
    struct http_media_type *media_type;
    char *type, *subtype;
    const char *ptr;
    size_t toklen;

    media_type = NULL;

#define HTTP_FAIL(fmt_, ...)                     \
    do {                                         \
        if (fmt_)                                \
        c_set_error(fmt_, ##__VA_ARGS__);    \
        http_media_type_delete(media_type); \
        return NULL;                             \
    } while (0)

    ptr = string;

    /* Type */
    toklen = strcspn(ptr, "/");
    if (toklen == 0)
        HTTP_FAIL("empty type");

    type = c_strndup(ptr, toklen);
    for (size_t i = 0; i < toklen; i++)
        type[i] = tolower(type[i]);

    ptr += toklen;

    /* Separator */
    if (*ptr != '/') {
        c_free(type);
        HTTP_FAIL("missing '/' after type");
    }
    ptr++;

    /* Subtype */
    toklen = strcspn(ptr, " ;");
    if (toklen == 0) {
        c_free(type);
        HTTP_FAIL("empty subtype");
    }

    subtype = c_strndup(ptr, toklen);
    for (size_t i = 0; i < toklen; i++)
        subtype[i] = tolower(subtype[i]);

    ptr += toklen;

    /* Media type */
    media_type = http_media_type_new(type, subtype);

    c_free(type);
    c_free(subtype);

    /* Parameters */
    while (*ptr != '\0') {
        char *name, *value;

        while (*ptr == ' ')
            ptr++;

        if (*ptr != ';')
            HTTP_FAIL("invalid parameter separator");

        ptr++;
        while (*ptr == ' ')
            ptr++;

        /* Name */
        toklen = strcspn(ptr, "=");

        name = c_strndup(ptr, toklen);
        for (size_t i = 0; i < toklen; i++)
            name[i] = tolower(name[i]);

        ptr += toklen;

        /* Separator */
        if (*ptr != '=') {
            c_free(name);
            HTTP_FAIL("missing '=' after parameter name");
        }
        ptr++;

        /* Value */
        if (*ptr == '"') {
            const char *vptr;

            /* Quoted value */
            ptr++;

            vptr = ptr;
            for (;;) {
                if (*vptr == '\0') {
                    c_free(name);
                    HTTP_FAIL("truncated quoted parameter");
                } else if (*vptr == '"' && *(vptr - 1) != '\\') {
                    break;
                }

                vptr++;
            }

            toklen = (size_t)(vptr - ptr);

            value = http_media_type_parameter_unescape(ptr, toklen);
            if (!value) {
                c_free(name);
                HTTP_FAIL("invalid quoted value: %s", c_get_error());
            }

            ptr += toklen + 1;
        } else {
            /* Token */
            toklen = strcspn(ptr, " ;");
            if (toklen == 0) {
                c_free(name);
                HTTP_FAIL("empty parameter value");
            }

            value = c_strndup(ptr, toklen);

            ptr += toklen;
        }

        /* Parameter */
        http_media_type_set_parameter_nocopy(media_type, name, value);
        c_free(name);
    }

#undef HTTP_FAIL

    http_media_type_update_strings(media_type);

    return media_type;
}

const char *
http_media_type_string(const struct http_media_type *media_type) {
    return media_type->string;
}

const char *
http_media_type_base_string(const struct http_media_type *media_type) {
    return media_type->base_string;
}

const char *
http_media_type_type(const struct http_media_type *media_type) {
    return media_type->type;
}

const char *
http_media_type_subtype(const struct http_media_type *media_type) {
    return media_type->subtype;
}

const char *
http_media_type_parameter(const struct http_media_type *media_type,
                          const char *name) {
    const char *value;

    if (c_hash_table_get(media_type->parameters, name, (void **)&value) == 0)
        return NULL;

    return value;
}

void
http_media_type_set_parameter(struct http_media_type *media_type,
                              const char *name, const char *value) {
    http_media_type_set_parameter_nocopy(media_type, name, c_strdup(value));
}

void
http_media_type_set_parameter_nocopy(struct http_media_type *media_type,
                                     const char *name, char *value) {
    char *oname, *ovalue;

    if (c_hash_table_insert2(media_type->parameters, c_strdup(name), value,
                             (void **)&oname, (void **)&ovalue) == 0) {
        c_free(oname);
        c_free(ovalue);
    }

    http_media_type_update_strings(media_type);
}

static void
http_media_type_update_strings(struct http_media_type *media_type) {
    struct c_buffer *buf;
    struct c_hash_table_iterator *it;
    const char *name, *value;

    buf = c_buffer_new();

    c_buffer_add_string(buf, media_type->type);
    c_buffer_add_string(buf, "/");
    c_buffer_add_string(buf, media_type->subtype);

    c_free(media_type->base_string);
    media_type->base_string = c_buffer_dup_string(buf);

    it = c_hash_table_iterate(media_type->parameters);
    while (c_hash_table_iterator_next(it, (void **)&name,
                                      (void **)&value) == 1) {
        c_buffer_add_string(buf, "; ");
        c_buffer_add_string(buf, name);
        c_buffer_add_string(buf, "=");

        http_media_type_parameter_to_buffer(value, buf);
    }
    c_hash_table_iterator_delete(it);

    c_free(media_type->string);
    media_type->string = c_buffer_extract_string(buf, NULL);

    c_buffer_delete(buf);
}

static void
http_media_type_parameter_to_buffer(const char *value, struct c_buffer *buf) {
    const char *iptr;
    bool quote;

    quote = false;
    iptr = value;
    while (*iptr != '\0') {
        if (*iptr == '\\' || *iptr == '"') {
            quote = true;
            break;
        }
        iptr++;
    }

    if (quote) {
        char *optr;
        size_t len;

        optr = c_buffer_reserve(buf, strlen(value) * 2 + 2);
        len = 0;

        *optr++ = '"';
        len++;

        iptr = value;
        while (*iptr != '\0') {
            if (*iptr == '\\' || *iptr == '"') {
                *optr++ = '\\';
                len++;
            }

            *optr++ = *iptr++;
            len++;
        }

        *optr++ = '"';
        len++;

        c_buffer_increase_length(buf, len);
    } else {
        c_buffer_add_string(buf, value);
    }
}

static char *
http_media_type_parameter_unescape(const char *data, size_t size) {
    char *value, *optr;
    const char *iptr;
    size_t ilen;

    value = c_malloc(size + 1);

    optr = value;
    iptr = data;
    ilen = size;

    while (ilen > 0) {
        if (*iptr == '\\') {
            iptr++;
            ilen--;
            if (ilen == 0) {
                c_set_error("truncated escape sequence");
                c_free(value);
                return NULL;
            }

            if (*iptr == '\\' || *iptr == '"') {
                *optr++ = *iptr;
            } else {
                c_set_error("inavlid escape sequence");
                c_free(value);
                return NULL;
            }
        } else {
            *optr++ = *iptr;
        }

        iptr++;
        ilen--;
    }

    *optr = '\0';

    return value;
}
