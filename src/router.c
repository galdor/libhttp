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

/* ---------------------------------------------------------------------------
 *  Route
 * ------------------------------------------------------------------------ */
struct http_route *
http_route_new(void) {
    struct http_route *route;

    route = c_malloc0(sizeof(struct http_route));

    return route;
}

void
http_route_delete(struct http_route *route) {
    if (!route)
        return;

    c_free0(route, sizeof(struct http_route));
}

/* ---------------------------------------------------------------------------
 *  Router
 * ------------------------------------------------------------------------ */
struct http_router *
http_router_new(void) {
    struct http_router *router;

    router = c_malloc0(sizeof(struct http_router));

    return router;
}

void
http_router_delete(struct http_router *router) {
    if (!router)
        return;

    c_free0(router, sizeof(struct http_router));
}

void
http_router_bind(struct http_router *router, const char *path,
                 http_route_cb cb, void *cb_arg) {
    struct http_route *route;

    route = http_route_new();

    route->cb = cb;
    route->cb_arg = cb_arg;
}

const struct http_route *
http_router_find_route(const struct http_router *router,
                       const struct http_uri *uri) {
    /* TODO */
    c_set_error("not implemented yet");
    return NULL;
}
