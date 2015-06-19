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

static bool http_uri_is_hex_digit(char);
static int http_uri_hex_digit_decode(char, int *);
static int http_uri_pct_decode(const char *, char *);
static void http_uri_pct_encode(char, char *);

/* ---------------------------------------------------------------------------
 *  Query parameter
 * ------------------------------------------------------------------------ */
static char *http_query_parameter_decode(const char *, size_t);
static void http_query_parameter_encode(const char *, struct c_buffer *);
static void http_query_parameters_to_buffer(const struct c_vector *,
                                            struct c_buffer *);

void
http_query_parameter_init(struct http_query_parameter *parameter) {
    memset(parameter, 0, sizeof(struct http_query_parameter));
}

void
http_query_parameter_free(struct http_query_parameter *parameter) {
    if (!parameter)
        return;

    c_free(parameter->name);
    c_free(parameter->value);

    memset(parameter, 0, sizeof(struct http_query_parameter));
}

struct c_vector *
http_query_parameters_parse(const char *string) {
    struct c_vector *parameters;
    const char *ptr;

    parameters = c_vector_new(sizeof(struct http_query_parameter));

    ptr = string;
    while (*ptr != '\0') {
        size_t toklen, name_sz, value_sz;
        const char *name_ptr, *value_ptr;
        struct http_query_parameter param;

        toklen = strcspn(ptr, "&;");

        name_ptr = ptr;
        name_sz = http_memcspn(ptr, toklen, "=");
        if (name_sz == toklen) {
            value_ptr = NULL;
            value_sz = 0;
        } else {
            value_ptr = ptr + name_sz + 1;
            value_sz = toklen - name_sz - 1;
        }

        http_query_parameter_init(&param);

        param.name = http_query_parameter_decode(name_ptr, name_sz);
        if (!param.name) {
            http_query_parameter_free(&param);
            goto error;
        }

        if (value_ptr) {
            param.value = http_query_parameter_decode(value_ptr, value_sz);
            if (!param.value) {
                http_query_parameter_free(&param);
                goto error;
            }
        }

        c_vector_append(parameters, &param);

        ptr += toklen;
        if (*ptr == '&' || *ptr == ';')
            ptr++;
    }

    return parameters;

error:
    for (size_t i = 0; i < c_vector_length(parameters); i++)
        http_query_parameter_free(c_vector_entry(parameters, i));
    c_vector_delete(parameters);

    return NULL;
}

static char *
http_query_parameter_decode(const char *data, size_t sz) {
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
        } else if (*ptr == '%') {
            char c;

            c_buffer_add(buf, start, (size_t)(ptr - start));

            if (http_uri_pct_decode(ptr, &c) == -1)
                goto error;

            c_buffer_add(buf, &c, 1);

            ptr += 3;
            len -= 3;

            start = ptr;
        } else if (*ptr == '+') {
            c_buffer_add(buf, start, (size_t)(ptr - start));
            c_buffer_add(buf, " ", 1);

            ptr++;
            len--;

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

static void
http_query_parameter_encode(const char *string, struct c_buffer *buf) {
    const char *iptr;
    char *optr;
    size_t len;

    iptr = string;
    len = 0;
    while (*iptr != '\0') {
        if ((*iptr >= 'a' && *iptr <= 'z')
         || (*iptr >= 'A' && *iptr <= 'Z')
         || (*iptr >= '0' && *iptr <= '9')
         || *iptr == '-' || *iptr == '.' || *iptr == '_') {
            len += 1;
        } else {
            len += 3;
        }

        iptr++;
    }

    optr = c_buffer_reserve(buf, len);

    iptr = string;
    while (*iptr != '\0') {
        if ((*iptr >= 'a' && *iptr <= 'z')
         || (*iptr >= 'A' && *iptr <= 'Z')
         || (*iptr >= '0' && *iptr <= '9')
         || *iptr == '-' || *iptr == '.' || *iptr == '_') {
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
http_query_parameters_to_buffer(const struct c_vector *parameters,
                                struct c_buffer *buf) {
    for (size_t i = 0; i < c_vector_length(parameters); i++) {
        struct http_query_parameter *parameter;

        parameter = c_vector_entry(parameters, i);

        if (i > 0)
            c_buffer_add(buf, "&", 1);

        http_query_parameter_encode(parameter->name, buf);

        if (parameter->value) {
            c_buffer_add(buf, "=", 1);
            http_query_parameter_encode(parameter->value, buf);
        }
    }
}

/* ---------------------------------------------------------------------------
 *  URI
 * ------------------------------------------------------------------------ */
static bool http_uri_is_scheme_first_char(char);
static bool http_uri_is_scheme_char(char);
static bool http_uri_is_sub_delims(char);
static bool http_uri_is_unreserved(char);

static char *http_uri_userinfo_decode(const char *, size_t);
static char *http_uri_host_decode(const char *, size_t);
static char *http_uri_path_decode(const char *, size_t);
static char *http_uri_query_decode(const char *, size_t);
static char *http_uri_fragment_decode(const char *, size_t);

static void http_uri_encode(const char *, struct c_buffer *);
static void http_uri_path_encode(const char *, struct c_buffer *);
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

    if (uri->query_parameters) {
        for (size_t i = 0; i < c_vector_length(uri->query_parameters); i++)
            http_query_parameter_free(c_vector_entry(uri->query_parameters, i));
        c_vector_delete(uri->query_parameters);
    }

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

        ptr += toklen;
    }

    if (*ptr == '?') {
        ptr++;

        /* Query */
        toklen = strcspn(ptr, "#");
        uri->query = c_strndup(ptr, toklen);
        if (!uri->query)
            HTTP_FAIL("cannot decode query: %s", c_get_error());

        uri->query_parameters = http_query_parameters_parse(uri->query);
        if (!uri->query_parameters)
            HTTP_FAIL("cannot parse query parameters: %s", c_get_error());

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

    if (uri->query_parameters) {
        c_buffer_add_string(buf, "?");
        http_query_parameters_to_buffer(uri->query_parameters, buf);
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

struct http_uri *
http_uri_clone(const struct http_uri *uri) {
    struct http_uri *new_uri;

    new_uri = http_uri_new();

    if (uri->scheme)
        new_uri->scheme = c_strdup(uri->scheme);
    if (uri->user)
        new_uri->user = c_strdup(uri->user);
    if (uri->password)
        new_uri->password = c_strdup(uri->password);
    if (uri->host)
        new_uri->host = c_strdup(uri->host);
    if (uri->port)
        new_uri->port = c_strdup(uri->port);
    new_uri->port_number = uri->port_number;
    if (uri->path)
        new_uri->path = c_strdup(uri->path);
    if (uri->query)
        new_uri->query = c_strdup(uri->query);
    if (uri->fragment)
        new_uri->fragment = c_strdup(uri->fragment);

    if (uri->query_parameters) {
        struct c_vector *parameters;

        parameters = c_vector_new(sizeof(struct http_query_parameter));
        for (size_t i = 0; i < c_vector_length(uri->query_parameters); i++) {
            struct http_query_parameter *parameter;
            struct http_query_parameter new_parameter;

            parameter = c_vector_entry(uri->query_parameters, i);

            http_query_parameter_init(&new_parameter);
            new_parameter.name = c_strdup(parameter->name);
            new_parameter.value = c_strdup(parameter->value);

            c_vector_append(parameters, &new_parameter);
        }

        new_uri->query_parameters = parameters;
    }

    return new_uri;
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

size_t
http_uri_nb_query_parameters(const struct http_uri *uri) {
    return c_vector_length(uri->query_parameters);
}

const char *
http_uri_nth_query_parameter(const struct http_uri *uri, size_t idx,
                             const char **pvalue) {
    const struct http_query_parameter *parameter;

    parameter = c_vector_entry(uri->query_parameters, idx);

    if (pvalue)
        *pvalue = parameter->value;
    return parameter->name;
}

bool
http_uri_has_query_parameter(const struct http_uri *uri, const char *name,
                             const char **pvalue) {
    const char *value;
    bool found;

    value = NULL;
    found = false;

    for (size_t i = 0; i < c_vector_length(uri->query_parameters); i++) {
        const struct http_query_parameter *parameter;

        parameter = c_vector_entry(uri->query_parameters, i);

        if (strcmp(parameter->name, name) == 0) {
            value = parameter->value;
            found = true;
        }
    }

    if (pvalue)
        *pvalue = value;
    return found;
}

const char *
http_uri_query_parameter(const struct http_uri *uri, const char *name) {
    const char *value;

    if (http_uri_has_query_parameter(uri, name, &value))
        return value;

    return NULL;
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
        } else {
            c_set_error("invalid user info character");
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

/* ---------------------------------------------------------------------------
 *  Misc
 * ------------------------------------------------------------------------ */
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

static void
http_uri_pct_encode(char c, char *ptr) {
    static const char *hex_digits = "0123456789abcdef";

    *ptr++ = '%';
    *ptr++ = hex_digits[(unsigned char)c >> 4];
    *ptr++ = hex_digits[(unsigned char)c & 0xf];
}
