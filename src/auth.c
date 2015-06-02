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

int http_auth_parse_basic_credentials(const char *, size_t, struct http_auth *);

struct http_auth *
http_auth_new(void) {
    struct http_auth *auth;

    auth = c_malloc0(sizeof(struct http_auth));

    return auth;
}

void
http_auth_delete(struct http_auth *auth) {
    if (!auth)
        return;

    switch (auth->scheme) {
    case HTTP_AUTH_SCHEME_BASIC:
        c_free(auth->u.basic.user);
        c_free(auth->u.basic.password);
        break;
    }

    c_free0(auth, sizeof(struct http_auth));
}

struct http_auth *
http_auth_parse_authorization(const char *string) {
    struct http_auth *auth;
    const char *ptr;
    size_t toklen;

    auth = http_auth_new();

    /* Scheme */
    ptr = string;
    toklen = strcspn(ptr, " \t");

    if (memcmp(ptr, "Basic", toklen) == 0) {
        char *credentials;
        size_t credentials_sz;

        auth->scheme = HTTP_AUTH_SCHEME_BASIC;

        ptr += toklen;
        while (*ptr == ' ' || *ptr == '\t')
            ptr++;

        toklen = strcspn(ptr, " \t");
        credentials = (char *)http_base64_decode(ptr, toklen, &credentials_sz);
        if (!credentials) {
            c_set_error("cannot decode credentials: %s", c_get_error());
            goto error;
        }

        if (http_auth_parse_basic_credentials(credentials, credentials_sz,
                                              auth) == -1) {
            c_set_error("cannot parse credentials: %s", c_get_error());
            c_free(credentials);
            goto error;
        }

        c_free(credentials);
    } else {
        c_set_error("unknown authentication scheme");
        goto error;
    }

    return auth;

error:
    http_auth_delete(auth);
    return NULL;
}

int
http_auth_parse_basic_credentials(const char *data, size_t sz,
                                  struct http_auth *auth) {
    const char *ptr;
    size_t len, toklen;

    assert(auth->scheme == HTTP_AUTH_SCHEME_BASIC);

    ptr = data;
    len = sz;

    /* User */
    toklen = http_memcspn(ptr, len, ":");
    if (toklen == len) {
        c_set_error("missing password");
        return -1;
    }

    if (toklen == 0) {
        c_set_error("empty user");
        return -1;
    }

    auth->u.basic.user = c_strndup(ptr, toklen);

    ptr += toklen + 1;
    len -= toklen + 1;

    /* Password */
    auth->u.basic.password = c_strndup(ptr, len);

    return 0;
}
