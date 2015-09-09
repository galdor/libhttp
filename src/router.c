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
static int http_route_cmp(const void *, const void *);
static bool http_route_matches_path(const struct http_route *,
                                    const struct http_path *);

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

    c_free(route->path_string);
    http_path_delete(route->path);

    c_free0(route, sizeof(struct http_route));
}

static int
http_route_cmp(const void *elt1, const void *elt2) {
    struct http_route *route1, *route2;
    size_t nbsegments1, nbsegments2;

    route1 = *(struct http_route **)elt1;
    route2 = *(struct http_route **)elt2;

    nbsegments1 = http_path_nb_segments(route1->path);
    nbsegments2 = http_path_nb_segments(route2->path);

    if (nbsegments1 < nbsegments2) {
        return -1;
    } else if (nbsegments2 < nbsegments1) {
        return 1;
    } else {
        for (size_t i = 0; i < nbsegments1; i++) {
            const char *segment1, *segment2;

            segment1 = http_path_segment(route1->path, i);
            segment2 = http_path_segment(route2->path, i);
        }
    }

    return 0;
}

static bool
http_route_matches_path(const struct http_route *route,
                        const struct http_path *path) {
    struct http_path *rpath;

    rpath = route->path;

    if (http_path_nb_segments(rpath) != http_path_nb_segments(path))
        return false;

    for (size_t i = 0; i < http_path_nb_segments(rpath); i++) {
        const char *segment, *rsegment;

        segment = http_path_segment(path, i);
        rsegment = http_path_segment(rpath, i);

        if (rsegment[0] == ':') {
            /* Named parameter */
            continue;
        }

        if (strcmp(rsegment, segment) != 0)
            return false;
    }

    return true;
}

/* ---------------------------------------------------------------------------
 *  Router
 * ------------------------------------------------------------------------ */
static void http_router_sort_routes(struct http_router *);

struct http_router *
http_router_new(void) {
    struct http_router *router;

    router = c_malloc0(sizeof(struct http_router));

    router->routes = c_ptr_vector_new();

    return router;
}

void
http_router_delete(struct http_router *router) {
    if (!router)
        return;

    for (size_t i = 0; i < c_ptr_vector_length(router->routes); i++)
        http_route_delete(c_ptr_vector_entry(router->routes, i));
    c_ptr_vector_delete(router->routes);

    c_free0(router, sizeof(struct http_router));
}

int
http_router_bind(struct http_router *router,
                 const char *path_string, enum http_method method,
                 http_route_cb cb, void *cb_arg) {
    struct http_route *route;
    struct http_path *path;

    path = http_path_parse(path_string);
    if (!path) {
        c_set_error("invalid path: %s", c_get_error());
        return -1;
    }

    route = http_route_new();

    route->path_string = c_strdup(path_string);
    route->path = path;
    route->method = method;

    route->cb = cb;
    route->cb_arg = cb_arg;

    c_ptr_vector_append(router->routes, route);

    http_router_sort_routes(router);

    return 0;
}

const struct http_route *
http_router_find_route(const struct http_router *router,
                       enum http_method method, const struct http_path *path,
                       enum http_status *pstatus) {
    bool matching_path;

    matching_path = false;

    for (size_t i = 0; i < c_ptr_vector_length(router->routes); i++) {
        const struct http_route *route;

        route = c_ptr_vector_entry(router->routes, i);

        if (!http_route_matches_path(route, path))
            continue;

        matching_path = true;

        if (route->method != method)
            continue;

        return route;
    }

    if (matching_path) {
        *pstatus = HTTP_405_METHOD_NOT_ALLOWED;
    } else {
        *pstatus = HTTP_404_NOT_FOUND;
    }

    return NULL;
}

static void
http_router_sort_routes(struct http_router *router) {
    qsort(c_ptr_vector_entries(router->routes),
          c_ptr_vector_length(router->routes),
          sizeof(struct http_route *),
          http_route_cmp);
}
