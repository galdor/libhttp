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

int
http_method_parse(const char *data, size_t sz, enum http_method *pmethod) {
    if (sz < 1) {
        c_set_error("unknown method");
        return -1;
    }

#define HTTP_METHOD_EQ(string_) \
    (sz == strlen(string_) && memcmp(data, string_, sz) == 0)

    if (data[0] == 'C') {
        if (HTTP_METHOD_EQ("CONNECT"))
            *pmethod = HTTP_CONNECT;
    } else if (data[0] == 'D') {
        if (HTTP_METHOD_EQ("DELETE"))
            *pmethod = HTTP_DELETE;
    } else if (data[0] == 'G') {
        if (HTTP_METHOD_EQ("GET"))
            *pmethod = HTTP_GET;
    } else if (data[0] == 'H') {
        if (HTTP_METHOD_EQ("HEAD"))
            *pmethod = HTTP_HEAD;
    } else if (data[0] == 'O') {
        if (HTTP_METHOD_EQ("OPTIONS"))
            *pmethod = HTTP_OPTIONS;
    } else if (data[0] == 'P') {
        if (sz < 2) {
            c_set_error("unknown method");
            return -1;
        }

        if (data[1] == 'O') {
            if (HTTP_METHOD_EQ("POST"))
                *pmethod = HTTP_POST;
        } else if (data[1] == 'U') {
            if (HTTP_METHOD_EQ("PUT"))
                *pmethod = HTTP_PUT;
        } else {
            return -1;
        }
    } else if (data[0] == 'T') {
        if (HTTP_METHOD_EQ("TRACE"))
            *pmethod = HTTP_TRACE;
    } else {
        c_set_error("unknown method");
        return -1;
    }

#undef HTTP_METHOD_EQ

    return 0;
}

const char *
http_method_to_string(enum http_method method) {
    static const char *strings[] = {
        [HTTP_GET]     = "GET",
        [HTTP_HEAD]    = "HEAD",
        [HTTP_POST]    = "POST",
        [HTTP_PUT]     = "PUT",
        [HTTP_DELETE]  = "DELETE",
        [HTTP_CONNECT] = "CONNECT",
        [HTTP_OPTIONS] = "OPTIONS",
        [HTTP_TRACE]   = "TRACE",
    };
    static size_t nb_strings = sizeof(strings) / sizeof(strings[0]);

    if (method >= nb_strings)
        return NULL;

    return strings[method];
}

int
http_version_parse(const char *data, size_t sz, enum http_version *pversion) {
    static const char *http_1_0 = "HTTP/1.0";
    static const char *http_1_1 = "HTTP/1.1";

    if (sz == strlen(http_1_1) && memcmp(data, http_1_1, sz) == 0) {
        *pversion = HTTP_1_1;
    } else if (sz == strlen(http_1_0) && memcmp(data, http_1_0, sz) == 0) {
        *pversion = HTTP_1_0;
    } else {
        c_set_error("version not supported");
        return -1;
    }

    return 0;
}

const char *
http_version_to_string(enum http_version version) {
    static const char *strings[] = {
        [HTTP_1_0] = "HTTP/1.0",
        [HTTP_1_1] = "HTTP/1.1",
    };
    static size_t nb_strings = sizeof(strings) / sizeof(strings[0]);

    if (version >= nb_strings)
        return NULL;

    return strings[version];
}

const char *
http_status_to_string(enum http_status status) {
    static const char *strings[] = {
        /* 1xx */
        [HTTP_100_CONTINUE]                      = "Continue",
        [HTTP_101_SWITCHING_PROTOCOLS]           = "Switching Protocols",

        /* 2xx */
        [HTTP_200_OK]                            = "OK",
        [HTTP_201_CREATED]                       = "Created",
        [HTTP_202_ACCEPTED]                      = "Accepted",
        [HTTP_203_NON_AUTHORITATIVE_INFORMATION] = "Non-Authoritative Information",
        [HTTP_204_NO_CONTENT]                    = "No Content",
        [HTTP_205_RESET_CONTENT]                 = "Reset Content",
        [HTTP_206_PARTIAL_CONTENT]               = "Partial Content",

        /* 3xx */
        [HTTP_300_MULTIPLE_CHOICES]              = "Multiple Choices",
        [HTTP_301_MOVED_PERMANENTLY]             = "Moved Permanently",
        [HTTP_302_FOUND]                         = "Found",
        [HTTP_303_SEE_OTHER]                     = "See Other",
        [HTTP_304_NOT_MODIFIED]                  = "Not Modified",
        [HTTP_305_USE_PROXY]                     = "Use Proxy",

        [HTTP_307_TEMPORARY_REDIRECT]            = "Temporary Redirect",

        /* 4xx */
        [HTTP_400_BAD_REQUEST]                   = "Bad Request",
        [HTTP_401_UNAUTHORIZED]                  = "Unauthorized",
        [HTTP_402_PAYMENT_REQUIRED]              = "Payment Required",
        [HTTP_403_FORBIDDEN]                     = "Forbidden",
        [HTTP_404_NOT_FOUND]                     = "Not Found",
        [HTTP_405_METHOD_NOT_ALLOWED]            = "Method Not Allowed",
        [HTTP_406_NOT_ACCEPTABLE]                = "Not Acceptable",
        [HTTP_407_PROXY_AUTHENTICATION_REQUIRED] = "Proxy Authentication "
                                                   "Required",
        [HTTP_408_REQUEST_TIMEOUT]               = "Request Timeout",
        [HTTP_409_CONFLICT]                      = "Conflict",
        [HTTP_410_GONE]                          = "Gone",
        [HTTP_411_LENGTH_REQUIRED]               = "Length Required",
        [HTTP_412_PRECONDITION_FAILED]           = "Precondition Failed",
        [HTTP_413_PAYLOAD_TOO_LARGE]             = "Payload Too Large",
        [HTTP_414_URI_TOO_LONG]                  = "URI Too Long",
        [HTTP_415_UNSUPPORTED_MEDIA_TYPE]        = "Unsupported Media Type",
        [HTTP_416_RANGE_NOT_SATISFIABLE]         = "Range Not Satisfiable",
        [HTTP_417_EXPECTATION_FAILED]            = "Expectation Failed",

        [HTTP_426_UPGRADE_REQUIRED]              = "Upgrade Required",

        [HTTP_428_PRECONDITION_REQUIRED]           = "Precondition Required",
        [HTTP_429_TOO_MANY_REQUESTS]               = "Too Many Requests",

        [HTTP_431_REQUEST_HEADER_FIELDS_TOO_LARGE] = "Request Header Fields "
                                                     "Too Large",

        /* 5xx */
        [HTTP_500_INTERNAL_SERVER_ERROR]         = "Internal Server Error",
        [HTTP_501_NOT_IMPLEMENTED]               = "Not Implemented",
        [HTTP_502_BAD_GATEWAY]                   = "Bad Gateway",
        [HTTP_503_SERVICE_UNAVAILABLE]           = "Service Unavailable",
        [HTTP_504_GATEWAY_TIMEOUT]               = "Gateway Timeout",
        [HTTP_505_HTTP_VERSION_NOT_SUPPORTED]    = "HTTP Version Not Supported",

        [HTTP_511_NETWORK_AUTHENTICATION_REQUIRED] = "Network Authentication "
                                                     "Required",
    };
    static size_t nb_strings = sizeof(strings) / sizeof(strings[0]);

    if (status >= nb_strings)
        return NULL;

    return strings[status];
}

bool
http_status_is_success(enum http_status status) {
    return status >= 200 && status < 300;
}

struct c_ptr_vector *
http_list_parse(const char *string) {
    struct c_ptr_vector *entries;
    const char *ptr, *start;

    entries = c_ptr_vector_new();

    ptr = string;

    start = NULL;
    for (;;) {
        if (*ptr == '\0' || *ptr == ',' || *ptr == ' ' || *ptr == '\t') {
            if (start) {
                char *token;

                token = c_strndup(start, (size_t)(ptr - start));
                c_ptr_vector_append(entries, token);

                start = NULL;
            }

            if (*ptr == '\0')
                break;
        } else {
            if (!start)
                start = ptr;
        }

        ptr++;
    }

    if (c_ptr_vector_length(entries) == 0) {
        c_ptr_vector_delete(entries);

        c_set_error("empty list");
        return NULL;
    }

    return entries;
}
