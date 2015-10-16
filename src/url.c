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

static bool http_url_is_hex_digit(char);
static int http_url_hex_digit_decode(char, int *);
static int http_url_pct_decode(const char *, char *);
static void http_url_pct_encode(char, char *);

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
        name_sz = c_memcspn(ptr, toklen, "=");
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

            if (http_url_pct_decode(ptr, &c) == -1)
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
            http_url_pct_encode(*iptr, optr);
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
static bool http_url_is_scheme_first_char(char);
static bool http_url_is_scheme_char(char);
static bool http_url_is_sub_delims(char);
static bool http_url_is_unreserved(char);

static char *http_url_userinfo_decode(const char *, size_t);
static char *http_url_host_decode(const char *, size_t);
static char *http_url_path_decode(const char *, size_t);
static char *http_url_query_decode(const char *, size_t);
static char *http_url_fragment_decode(const char *, size_t);

static void http_url_encode(const char *, struct c_buffer *);
static void http_url_path_encode(const char *, struct c_buffer *);
static void http_url_fragment_encode(const char *, struct c_buffer *);

struct http_url *
http_url_new(void) {
    struct http_url *url;

    url = c_malloc0(sizeof(struct http_url));

    return url;
}

void
http_url_delete(struct http_url *url) {
    if (!url)
        return;

    c_free(url->scheme);
    c_free(url->user);
    c_free(url->password);
    c_free(url->host);
    c_free(url->port);
    c_free(url->path);
    c_free(url->query);
    c_free(url->fragment);

    if (url->query_parameters) {
        for (size_t i = 0; i < c_vector_length(url->query_parameters); i++)
            http_query_parameter_free(c_vector_entry(url->query_parameters, i));
        c_vector_delete(url->query_parameters);
    }

    c_free0(url, sizeof(struct http_url));
}

struct http_url *
http_url_parse(const char *string) {
    struct http_url *url;
    const char *ptr, *start, *end, *at, *colon;
    size_t toklen;

    url = http_url_new();

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
    if (!(http_url_is_scheme_first_char(*ptr)))
        HTTP_FAIL("invalid first character in scheme");
    for (;;) {
        if (*ptr == '\0' || *ptr == ':') {
            toklen = (size_t)(ptr - start);
            if (toklen == 0)
                HTTP_FAIL("empty scheme");
            url->scheme = c_strndup(start, toklen);
            break;
        } else if (!http_url_is_scheme_char(*ptr)) {
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

        url->user = http_url_userinfo_decode(ptr, toklen);
        if (!url->user)
            HTTP_FAIL("cannot decode user: %s", c_get_error());

        if (colon) {
            /* Password */
            toklen = (size_t)(at - colon - 1);

            url->password = http_url_userinfo_decode(colon + 1, toklen);
            if (!url->password)
                HTTP_FAIL("cannot decode password: %s", c_get_error());
        }

        ptr = at + 1;
    }

    /* Host */
    if (*ptr == '[') {
        /* IPv6 address */

        ptr++;
        toklen = strcspn(ptr, "]");
    } else {
        toklen = strcspn(ptr, ":/?#");
    }

    url->host = http_url_host_decode(ptr, toklen);
    if (!url->host)
        HTTP_FAIL("cannot decode host: %s", c_get_error());

    ptr += toklen;
    if (*ptr == ']')
        ptr++;

    if (*ptr == ':') {
        size_t port_sz;

        ptr++;

        /* Port */
        toklen = strcspn(ptr, "/?#");
        if (toklen == 0)
            HTTP_FAIL("empty port number");

        url->port = c_strndup(ptr, toklen);
        if (c_parse_u16(url->port, &url->port_number, &port_sz) == -1)
            HTTP_FAIL("invalid port number: %s", c_get_error());
        if (port_sz != strlen(url->port))
            HTTP_FAIL("invalid trailing data after port number");
        if (url->port_number == 0)
            HTTP_FAIL("invalid port number");

        ptr += toklen;
    }

path:
    if (*ptr == '/') {
        /* Path */
        toklen = strcspn(ptr, "?#");
        url->path = http_url_path_decode(ptr, toklen);
        if (!url->path)
            HTTP_FAIL("cannot decode path: %s", c_get_error());

        ptr += toklen;
    }

    if (*ptr == '?') {
        ptr++;

        /* Query */
        toklen = strcspn(ptr, "#");
        url->query = c_strndup(ptr, toklen);
        if (!url->query)
            HTTP_FAIL("cannot decode query: %s", c_get_error());

        url->query_parameters = http_query_parameters_parse(url->query);
        if (!url->query_parameters)
            HTTP_FAIL("cannot parse query parameters: %s", c_get_error());

        ptr += toklen;
    }

    if (*ptr == '#') {
        ptr++;

        /* Fragment */
        toklen = strlen(ptr);
        url->fragment = http_url_fragment_decode(ptr, toklen);
        if (!url->fragment)
            HTTP_FAIL("cannot decode fragment: %s", c_get_error());

        ptr += toklen;
    }

#undef HTTP_FAIL

    return url;

error:
    http_url_delete(url);
    return NULL;
}

void
http_url_to_buffer(const struct http_url *url, struct c_buffer *buf) {
    if (url->scheme)
        c_buffer_add_printf(buf, "%s:", url->scheme);

    if (url->host) {
        c_buffer_add_string(buf, "//");

        if (url->user) {
            http_url_encode(url->user, buf);

            if (url->password) {
                c_buffer_add_string(buf, ":");
                http_url_encode(url->password, buf);
            }

            c_buffer_add_string(buf, "@");
        }

        http_url_encode(url->host, buf);

        if (url->port)
            c_buffer_add_printf(buf, ":%u", url->port_number);
    }

    if (url->path) {
        http_url_path_encode(url->path, buf);
    } else {
        c_buffer_add_string(buf, "/");
    }

    if (url->query_parameters) {
        c_buffer_add_string(buf, "?");
        http_query_parameters_to_buffer(url->query_parameters, buf);
    }

    if (url->fragment) {
        c_buffer_add_string(buf, "#");
        http_url_fragment_encode(url->fragment, buf);
    }
}

char *
http_url_to_string(const struct http_url *url) {
    struct c_buffer *buf;
    char *string;

    buf = c_buffer_new();
    http_url_to_buffer(url, buf);

    string = c_buffer_extract_string(buf, NULL);
    c_buffer_delete(buf);

    return string;
}

struct http_url *
http_url_clone(const struct http_url *url) {
    struct http_url *new_url;

    new_url = http_url_new();

    if (url->scheme)
        new_url->scheme = c_strdup(url->scheme);
    if (url->user)
        new_url->user = c_strdup(url->user);
    if (url->password)
        new_url->password = c_strdup(url->password);
    if (url->host)
        new_url->host = c_strdup(url->host);
    if (url->port)
        new_url->port = c_strdup(url->port);
    new_url->port_number = url->port_number;
    if (url->path)
        new_url->path = c_strdup(url->path);
    if (url->query)
        new_url->query = c_strdup(url->query);
    if (url->fragment)
        new_url->fragment = c_strdup(url->fragment);

    if (url->query_parameters) {
        struct c_vector *parameters;

        parameters = c_vector_new(sizeof(struct http_query_parameter));
        for (size_t i = 0; i < c_vector_length(url->query_parameters); i++) {
            struct http_query_parameter *parameter;
            struct http_query_parameter new_parameter;

            parameter = c_vector_entry(url->query_parameters, i);

            http_query_parameter_init(&new_parameter);
            new_parameter.name = c_strdup(parameter->name);
            new_parameter.value = c_strdup(parameter->value);

            c_vector_append(parameters, &new_parameter);
        }

        new_url->query_parameters = parameters;
    }

    return new_url;
}

const char *
http_url_scheme(const struct http_url *url) {
    return url->scheme;
}

const char *
http_url_user(const struct http_url *url) {
    return url->user;
}

const char *
http_url_password(const struct http_url *url) {
    return url->password;
}

const char *
http_url_host(const struct http_url *url) {
    return url->host;
}

const char *
http_url_port(const struct http_url *url) {
    return url->port;
}

uint16_t
http_url_port_number(const struct http_url *url) {
    return url->port_number;
}

const char *
http_url_path(const struct http_url *url) {
    return url->path;
}

const char *
http_url_query(const struct http_url *url) {
    return url->query;
}

const char *
http_url_fragment(const struct http_url *url) {
    return url->fragment;
}

void
http_url_set_scheme(struct http_url *url, const char *string) {
    c_free(url->scheme);
    url->scheme = c_strdup(string);
}

void
http_url_set_user(struct http_url *url, const char *string) {
    c_free(url->user);
    url->user = c_strdup(string);
}

void
http_url_set_password(struct http_url *url, const char *string) {
    c_free(url->password);
    url->password = c_strdup(string);
}

void
http_url_set_host(struct http_url *url, const char *string) {
    c_free(url->host);
    url->host = c_strdup(string);
}

void
http_url_set_port(struct http_url *url, uint16_t port) {
    url->port_number = port;
    c_free(url->port);
    c_asprintf(&url->port, "%u", port);
}

void
http_url_set_path(struct http_url *url, const char *string) {
    c_free(url->path);
    url->path = c_strdup(string);
}

void
http_url_set_query(struct http_url *url, const char *string) {
    c_free(url->query);
    url->query = c_strdup(string);
}

void
http_url_set_fragment(struct http_url *url, const char *string) {
    c_free(url->fragment);
    url->fragment = c_strdup(string);
}

size_t
http_url_nb_query_parameters(const struct http_url *url) {
    if (!url->query_parameters)
        return 0;

    return c_vector_length(url->query_parameters);
}

const char *
http_url_nth_query_parameter(const struct http_url *url, size_t idx,
                             const char **pvalue) {
    const struct http_query_parameter *parameter;

    assert(url->query_parameters);

    parameter = c_vector_entry(url->query_parameters, idx);

    if (pvalue)
        *pvalue = parameter->value;
    return parameter->name;
}

bool
http_url_has_query_parameter(const struct http_url *url, const char *name,
                             const char **pvalue) {
    const char *value;
    bool found;

    value = NULL;
    found = false;

    if (!url->query_parameters)
        return false;

    for (size_t i = 0; i < c_vector_length(url->query_parameters); i++) {
        const struct http_query_parameter *parameter;

        parameter = c_vector_entry(url->query_parameters, i);

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
http_url_query_parameter(const struct http_url *url, const char *name) {
    const char *value;

    if (http_url_has_query_parameter(url, name, &value))
        return value;

    return NULL;
}

static bool
http_url_is_scheme_first_char(char c) {
    return (c >= 'a' && c <= 'z')
        || (c >= 'A' && c <= 'Z');
}

static bool
http_url_is_scheme_char(char c) {
    return (c >= 'a' && c <= 'z')
        || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9')
        || c == '+' || c == '-' || c == '.';
}

static bool
http_url_is_sub_delims(char c) {
    return c == '!' || c == '$' || c == '$' || c == '&' || c == '\''
        || c == '(' || c == ')' || c == '*' || c == '+' || c == ','
        || c == ';' || c == '=';
}

static bool
http_url_is_unreserved(char c) {
    return (c >= 'a' && c <= 'z')
        || (c >= 'A' && c <= 'Z')
        || (c >= '0' && c <= '9')
        || c == '-' || c == '.' || c == '_' || c == '=';
}

static char *
http_url_userinfo_decode(const char *data, size_t sz) {
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
        } else if (http_url_is_unreserved(*ptr)
                || http_url_is_sub_delims(*ptr)) {
            ptr++;
            len--;
        } else if (*ptr == '%') {
            char c;

            c_buffer_add(buf, start, (size_t)(ptr - start));

            if (http_url_pct_decode(ptr, &c) == -1)
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
http_url_host_decode(const char *data, size_t sz) {
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

            if (http_url_pct_decode(ptr, &c) == -1)
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
http_url_path_decode(const char *data, size_t sz) {
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

            if (http_url_pct_decode(ptr, &c) == -1)
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
http_url_query_decode(const char *data, size_t sz) {
    return http_url_fragment_decode(data, sz);
}

static char *
http_url_fragment_decode(const char *data, size_t sz) {
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
        } else if (http_url_is_unreserved(*ptr)
                || http_url_is_sub_delims(*ptr)
                || *ptr == ':' || *ptr == '@'
                || *ptr == '/' || *ptr == '?') {
            ptr++;
            len--;
        } else if (*ptr == '%') {
            char c;

            c_buffer_add(buf, start, (size_t)(ptr - start));

            if (http_url_pct_decode(ptr, &c) == -1)
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
http_url_encode(const char *string, struct c_buffer *buf) {
    const char *iptr;
    char *optr;
    size_t len;

    iptr = string;
    len = 0;
    while (*iptr != '\0') {
        if (http_url_is_unreserved(*iptr)
         || http_url_is_sub_delims(*iptr)) {
            len += 1;
        } else {
            len += 3;
        }

        iptr++;
    }

    optr = c_buffer_reserve(buf, len);

    iptr = string;
    while (*iptr != '\0') {
        if (http_url_is_unreserved(*iptr)
         || http_url_is_sub_delims(*iptr)) {
            *optr++ = *iptr++;
        } else {
            http_url_pct_encode(*iptr, optr);
            iptr += 1;
            optr += 3;
        }
    }

    c_buffer_increase_length(buf, len);
}

static void
http_url_path_encode(const char *string, struct c_buffer *buf) {
    const char *iptr;
    char *optr;
    size_t len;

    iptr = string;
    len = 0;
    while (*iptr != '\0') {
        if (http_url_is_unreserved(*iptr)
         || http_url_is_sub_delims(*iptr)
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
        if (http_url_is_unreserved(*iptr)
         || http_url_is_sub_delims(*iptr)
         || *iptr == '/') {
            *optr++ = *iptr++;
        } else {
            http_url_pct_encode(*iptr, optr);
            iptr += 1;
            optr += 3;
        }
    }

    c_buffer_increase_length(buf, len);
}

static void
http_url_fragment_encode(const char *string, struct c_buffer *buf) {
    const char *iptr;
    char *optr;
    size_t len;

    iptr = string;
    len = 0;
    while (*iptr != '\0') {
        if (http_url_is_unreserved(*iptr)
         || http_url_is_sub_delims(*iptr)
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
        if (http_url_is_unreserved(*iptr)
         || http_url_is_sub_delims(*iptr)
         || *iptr == ':' || *iptr == '@' || *iptr == '/' || *iptr == '?') {
            *optr++ = *iptr++;
        } else {
            http_url_pct_encode(*iptr, optr);
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
http_url_is_hex_digit(char c) {
    return (c >= '0' && c <= '9')
        || (c >= 'a' && c <= 'f')
        || (c >= 'F' && c <= 'F');
}

static int
http_url_hex_digit_decode(char c, int *pval) {
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
http_url_pct_decode(const char *ptr, char *pc) {
    int d1, d2;

    if (ptr[0] != '%') {
        c_set_error("invalid escape sequence");
        return -1;
    }

    if (http_url_hex_digit_decode(ptr[1], &d1) == -1)
        return -1;
    if (http_url_hex_digit_decode(ptr[2], &d2) == -1)
        return -1;

    *pc = (d1 << 4) | d2;

    return 0;
}

static void
http_url_pct_encode(char c, char *ptr) {
    static const char *hex_digits = "0123456789abcdef";

    *ptr++ = '%';
    *ptr++ = hex_digits[(unsigned char)c >> 4];
    *ptr++ = hex_digits[(unsigned char)c & 0xf];
}
