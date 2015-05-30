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

static char *http_uri_component_decode(const char *, size_t);

static bool http_uri_is_scheme_first_char(char);
static bool http_uri_is_scheme_char(char);
static bool http_uri_is_sub_delims(char);
static bool http_uri_is_unreserved(char);

static bool http_uri_is_hex_digit(char);
static int http_uri_hex_digit_decode(char, int *);
static int http_uri_pct_decode(const char *, char *);

static char *http_uri_userinfo_decode(const char *, size_t);
static char *http_uri_host_decode(const char *, size_t);
static char *http_uri_path_decode(const char *, size_t);
static char *http_uri_query_decode(const char *, size_t);
static char *http_uri_fragment_decode(const char *, size_t);

static void http_uri_pct_encode(char, char *);
static void http_uri_encode(const char *, struct c_buffer *);
static void http_uri_path_encode(const char *, struct c_buffer *);
static void http_uri_query_encode(const char *, struct c_buffer *);
static void http_uri_fragment_encode(const char *, struct c_buffer *);

struct http_uri *
http_uri_new(void) {
    struct http_uri *uri;

    uri = c_malloc0(sizeof(struct http_uri));

    return uri;
}

void
http_uri_delete(struct http_uri *uri) {
    if (!uri)
        return;

    c_free(uri->scheme);
    c_free(uri->user);
    c_free(uri->password);
    c_free(uri->host);
    c_free(uri->port);
    c_free(uri->path);
    c_free(uri->query);
    c_free(uri->fragment);

    c_free0(uri, sizeof(struct http_uri));
}

struct http_uri *
http_uri_parse(const char *string) {
    struct http_uri *uri;
    const char *ptr, *start, *end, *at, *colon;
    size_t toklen;

    uri = http_uri_new();

    ptr = string;

#define HTTP_FAIL(fmt_, ...)              \
    do {                                  \
        c_set_error(fmt_, ##__VA_ARGS__); \
        goto error;                       \
    } while (0)

    /* Scheme */
    if (*ptr == '/')
        goto path;

    start = ptr;
    if (!(http_uri_is_scheme_first_char(*ptr)))
        HTTP_FAIL("invalid first character in scheme");
    for (;;) {
        if (*ptr == '\0' || *ptr == ':') {
            toklen = (size_t)(ptr - start);
            if (toklen == 0)
                HTTP_FAIL("empty scheme");
            uri->scheme = c_strndup(start, toklen);
            break;
        } else if (!http_uri_is_scheme_char(*ptr)) {
            HTTP_FAIL("invalid character in scheme");
        }

        ptr++;
    }

    if (*ptr == ':')
        ptr++;

    /* Authority */
    if (ptr[0] != '/' || ptr[1] != '/')
        HTTP_FAIL("invalid characters after scheme");
    ptr += 2;

    end = ptr + strcspn(ptr, "/?#");

    at = strchr(ptr, '@');
    if (at && at < end) {
        /* User */
        colon = strchr(ptr, ':');

        if (colon) {
            toklen = (size_t)(colon - ptr);
        } else {
            toklen = (size_t)(at - ptr);
        }

        uri->user = http_uri_userinfo_decode(ptr, toklen);
        if (!uri->user)
            HTTP_FAIL("cannot decode user: %s", c_get_error());

        if (colon) {
            /* Password */
            toklen = (size_t)(at - colon - 1);

            uri->password = http_uri_userinfo_decode(colon + 1, toklen);
            if (!uri->password)
                HTTP_FAIL("cannot decode password: %s", c_get_error());
        }

        ptr = at + 1;
    }

    /* Host */
    toklen = strcspn(ptr, ":/?#");
    uri->host = http_uri_host_decode(ptr, toklen);
    if (!uri->host)
        HTTP_FAIL("cannot decode host: %s", c_get_error());

    ptr += toklen;

    if (*ptr == ':') {
        size_t port_sz;

        ptr++;

        /* Port */
        toklen = strcspn(ptr, "/?#");
        if (toklen == 0)
            HTTP_FAIL("empty port number");

        uri->port = c_strndup(ptr, toklen);
        if (c_parse_u16(uri->port, &uri->port_number, &port_sz) == -1)
            HTTP_FAIL("invalid port number: %s", c_get_error());
        if (port_sz != strlen(uri->port))
            HTTP_FAIL("invalid trailing data after port number");
        if (uri->port_number == 0)
            HTTP_FAIL("invalid port number");

        ptr += toklen;
    }

path:
    if (*ptr == '/') {
        /* Path */
        toklen = strcspn(ptr, "?#");
        uri->path = http_uri_path_decode(ptr, toklen);
        if (!uri->path)
            HTTP_FAIL("cannot decode path: %s", c_get_error());

        /* TODO parse path components */

        ptr += toklen;
    }

    if (*ptr == '?') {
        ptr++;

        /* Query */
        toklen = strcspn(ptr, "#");
        uri->query = http_uri_query_decode(ptr, toklen);
        if (!uri->query)
            HTTP_FAIL("cannot decode query: %s", c_get_error());

        /* TODO parse query parameters */

        ptr += toklen;
    }

    if (*ptr == '#') {
        ptr++;

        /* Fragment */
        toklen = strlen(ptr);
        uri->fragment = http_uri_fragment_decode(ptr, toklen);
        if (!uri->fragment)
            HTTP_FAIL("cannot decode fragment: %s", c_get_error());

        ptr += toklen;
    }

#undef HTTP_FAIL

    return uri;

error:
    http_uri_delete(uri);
    return NULL;
}

void
http_uri_to_buffer(const struct http_uri *uri, struct c_buffer *buf) {
    if (uri->scheme)
        c_buffer_add_printf(buf, "%s:", uri->scheme);

    if (uri->host) {
        c_buffer_add_string(buf, "//");

        if (uri->user) {
            http_uri_encode(uri->user, buf);

            if (uri->password) {
                c_buffer_add_string(buf, ":");
                http_uri_encode(uri->password, buf);
            }

            c_buffer_add_string(buf, "@");
        }

        http_uri_encode(uri->host, buf);

        if (uri->port)
            c_buffer_add_printf(buf, ":%u", uri->port_number);
    }

    if (uri->path) {
        http_uri_path_encode(uri->path, buf);
    } else {
        c_buffer_add_string(buf, "/");
    }

    if (uri->query) {
        c_buffer_add_string(buf, "?");
        http_uri_query_encode(uri->query, buf);
    }

    if (uri->fragment) {
        c_buffer_add_string(buf, "#");
        http_uri_fragment_encode(uri->fragment, buf);
    }
}

char *
http_uri_to_string(const struct http_uri *uri) {
    struct c_buffer *buf;
    char *string;

    buf = c_buffer_new();
    http_uri_to_buffer(uri, buf);

    string = c_buffer_extract_string(buf, NULL);
    c_buffer_delete(buf);

    return string;
}

const char *
http_uri_scheme(const struct http_uri *uri) {
    return uri->scheme;
}

const char *
http_uri_user(const struct http_uri *uri) {
    return uri->user;
}

const char *
http_uri_password(const struct http_uri *uri) {
    return uri->password;
}

const char *
http_uri_host(const struct http_uri *uri) {
    return uri->host;
}

const char *
http_uri_port(const struct http_uri *uri) {
    return uri->port;
}

uint16_t
http_uri_port_number(const struct http_uri *uri) {
    return uri->port_number;
}

const char *
http_uri_path(const struct http_uri *uri) {
    return uri->path;
}

const char *
http_uri_query(const struct http_uri *uri) {
    return uri->query;
}

const char *
http_uri_fragment(const struct http_uri *uri) {
    return uri->fragment;
}

static bool
http_uri_is_scheme_first_char(char c) {
    return (c >= 'a' && c <= 'z')
        || (c >= 'A' && c <= 'Z');
}

static bool
http_uri_is_scheme_char(char c) {
    return (c >= 'a' && c <= 'z')
        || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9')
        || c == '+' || c == '-' || c == '.';
}

static bool
http_uri_is_sub_delims(char c) {
    return c == '!' || c == '$' || c == '$' || c == '&' || c == '\''
        || c == '(' || c == ')' || c == '*' || c == '+' || c == ','
        || c == ';' || c == '=';
}

static bool
http_uri_is_unreserved(char c) {
    return (c >= 'a' && c <= 'z')
        || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9')
        || c == '-' || c == '.' || c == '_' || c == '=';
}

static bool
http_uri_is_hex_digit(char c) {
    return (c >= '0' && c <= '9')
        || (c >= 'a' && c <= 'f')
        || (c >= 'F' && c <= 'F');
}

static int
http_uri_hex_digit_decode(char c, int *pval) {
    if (c >= '0' && c <= '9') {
        *pval = c - '0';
    } else if (c >= 'a' && c <= 'f') {
        *pval = 10 + c - 'a';
    } else if (c >= 'A' && c <= 'F') {
        *pval = 10 + c - 'A';
    } else {
        return -1;
    }

    return 0;
}

static int
http_uri_pct_decode(const char *ptr, char *pc) {
    int d1, d2;

    if (ptr[0] != '%') {
        c_set_error("invalid escape sequence");
        return -1;
    }

    if (http_uri_hex_digit_decode(ptr[1], &d1) == -1)
        return -1;
    if (http_uri_hex_digit_decode(ptr[2], &d2) == -1)
        return -1;

    *pc = (d1 << 4) | d2;

    return 0;
}

static char *
http_uri_userinfo_decode(const char *data, size_t sz) {
    struct c_buffer *buf;
    char *string;
    const char *ptr, *start;
    size_t len;

    buf = c_buffer_new();

    ptr = data;
    len = sz;

    start = ptr;
    for (;;) {
        if (len == 0) {
            c_buffer_add(buf, start, (size_t)(ptr - start));
            break;
        } else if (http_uri_is_unreserved(*ptr)
                || http_uri_is_sub_delims(*ptr)) {
            ptr++;
            len--;
        } else if (*ptr == '%') {
            char c;

            c_buffer_add(buf, start, (size_t)(ptr - start));

            if (http_uri_pct_decode(ptr, &c) == -1)
                goto error;

            c_buffer_add(buf, &c, 1);

            ptr += 3;
            len -= 3;

            start = ptr;
        }
    }

    string = c_buffer_extract_string(buf, NULL);
    c_buffer_delete(buf);
    return string;

error:
    c_buffer_delete(buf);
    return NULL;
}

static char *
http_uri_host_decode(const char *data, size_t sz) {
    struct c_buffer *buf;
    char *string;
    const char *ptr, *start;
    size_t len;

    /* TODO Validate host names, ipv4 addresses, and ipv6 addresses */

    buf = c_buffer_new();

    ptr = data;
    len = sz;

    start = ptr;
    for (;;) {
        if (len == 0) {
            c_buffer_add(buf, start, (size_t)(ptr - start));
            break;
        } else if (*ptr == '%') {
            char c;

            c_buffer_add(buf, start, (size_t)(ptr - start));

            if (http_uri_pct_decode(ptr, &c) == -1)
                goto error;

            c_buffer_add(buf, &c, 1);

            ptr += 3;
            len -= 3;

            start = ptr;
        } else {
            ptr++;
            len--;
        }
    }

    string = c_buffer_extract_string(buf, NULL);
    c_buffer_delete(buf);
    return string;

error:
    c_buffer_delete(buf);
    return NULL;
}

static char *
http_uri_path_decode(const char *data, size_t sz) {
    struct c_buffer *buf;
    char *string;
    const char *ptr, *start;
    size_t len;

    /* TODO Validate various types of paths */

    buf = c_buffer_new();

    ptr = data;
    len = sz;

    start = ptr;
    for (;;) {
        if (len == 0) {
            c_buffer_add(buf, start, (size_t)(ptr - start));
            break;
        } else if (*ptr == '%') {
            char c;

            c_buffer_add(buf, start, (size_t)(ptr - start));

            if (http_uri_pct_decode(ptr, &c) == -1)
                goto error;

            c_buffer_add(buf, &c, 1);

            ptr += 3;
            len -= 3;

            start = ptr;
        } else {
            ptr++;
            len--;
        }
    }

    string = c_buffer_extract_string(buf, NULL);
    c_buffer_delete(buf);
    return string;

error:
    c_buffer_delete(buf);
    return NULL;
}

static char *
http_uri_query_decode(const char *data, size_t sz) {
    return http_uri_fragment_decode(data, sz);
}

static char *
http_uri_fragment_decode(const char *data, size_t sz) {
    struct c_buffer *buf;
    char *string;
    const char *ptr, *start;
    size_t len;

    buf = c_buffer_new();

    ptr = data;
    len = sz;

    start = ptr;
    for (;;) {
        if (len == 0) {
            c_buffer_add(buf, start, (size_t)(ptr - start));
            break;
        } else if (http_uri_is_unreserved(*ptr)
                || http_uri_is_sub_delims(*ptr)
                || *ptr == ':' || *ptr == '@'
                || *ptr == '/' || *ptr == '?') {
            ptr++;
            len--;
        } else if (*ptr == '%') {
            char c;

            c_buffer_add(buf, start, (size_t)(ptr - start));

            if (http_uri_pct_decode(ptr, &c) == -1)
                goto error;

            c_buffer_add(buf, &c, 1);

            ptr += 3;
            len -= 3;

            start = ptr;
        } else {
            c_set_error("invalid query/fragment character");
            goto error;
        }
    }

    string = c_buffer_extract_string(buf, NULL);
    c_buffer_delete(buf);
    return string;

error:
    c_buffer_delete(buf);
    return NULL;
}

static void
http_uri_pct_encode(char c, char *ptr) {
    static const char *hex_digits = "0123456789abcdef";

    *ptr++ = '%';
    *ptr++ = hex_digits[(unsigned char)c >> 4];
    *ptr++ = hex_digits[(unsigned char)c & 0xf];
}

static void
http_uri_encode(const char *string, struct c_buffer *buf) {
    const char *iptr;
    char *optr;
    size_t len;

    iptr = string;
    len = 0;
    while (*iptr != '\0') {
        if (http_uri_is_unreserved(*iptr)
         || http_uri_is_sub_delims(*iptr)) {
            len += 1;
        } else {
            len += 3;
        }

        iptr++;
    }

    optr = c_buffer_reserve(buf, len);

    iptr = string;
    while (*iptr != '\0') {
        if (http_uri_is_unreserved(*iptr)
         || http_uri_is_sub_delims(*iptr)) {
            *optr++ = *iptr++;
        } else {
            http_uri_pct_encode(*iptr, optr);
            iptr += 1;
            optr += 3;
        }
    }

    c_buffer_increase_length(buf, len);
}

static void
http_uri_path_encode(const char *string, struct c_buffer *buf) {
    const char *iptr;
    char *optr;
    size_t len;

    iptr = string;
    len = 0;
    while (*iptr != '\0') {
        if (http_uri_is_unreserved(*iptr)
         || http_uri_is_sub_delims(*iptr)
         || *iptr == '/') {
            len += 1;
        } else {
            len += 3;
        }

        iptr++;
    }

    optr = c_buffer_reserve(buf, len);

    iptr = string;
    while (*iptr != '\0') {
        if (http_uri_is_unreserved(*iptr)
         || http_uri_is_sub_delims(*iptr)
         || *iptr == '/') {
            *optr++ = *iptr++;
        } else {
            http_uri_pct_encode(*iptr, optr);
            iptr += 1;
            optr += 3;
        }
    }

    c_buffer_increase_length(buf, len);
}

static void
http_uri_query_encode(const char *string, struct c_buffer *buf) {
    return http_uri_fragment_encode(string, buf);
}

static void
http_uri_fragment_encode(const char *string, struct c_buffer *buf) {
    const char *iptr;
    char *optr;
    size_t len;

    iptr = string;
    len = 0;
    while (*iptr != '\0') {
        if (http_uri_is_unreserved(*iptr)
         || http_uri_is_sub_delims(*iptr)
         || *iptr == ':' || *iptr == '@' || *iptr == '/' || *iptr == '?') {
            len += 1;
        } else {
            len += 3;
        }

        iptr++;
    }

    optr = c_buffer_reserve(buf, len);

    iptr = string;
    while (*iptr != '\0') {
        if (http_uri_is_unreserved(*iptr)
         || http_uri_is_sub_delims(*iptr)
         || *iptr == ':' || *iptr == '@' || *iptr == '/' || *iptr == '?') {
            *optr++ = *iptr++;
        } else {
            http_uri_pct_encode(*iptr, optr);
            iptr += 1;
            optr += 3;

            iptr++;
        }
    }

    c_buffer_increase_length(buf, len);
}
