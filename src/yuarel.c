/**
 * Copyright (C) 2016 Jack Engqvist Johansson
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "yuarel.h"

/**
 * Parse a non null terminated string into an integer.
 *
 * str: pointer to the string containing the number.
 * len: Number of characters to parse.
 */
static inline int
natoi(char *str, size_t len)
{
	int i, r = 0;
	for (i = 0; i < len; i++) {
		r *= 10;
		r += str[i] - '0';
	}

	return r;
}

/**
 * Parse a URL string to a struct.
 *
 * url: pointer to the struct where to store the parsed URL parts.
 * u:   the URL string to be parsed.
 *
 * Returns 0 on success, otherwise -1.
 */
int
yuarel_parse(struct yuarel *url, char *u)
{
	if (NULL == url || NULL == u) {
		return -1;
	}

	memset(url, 0, sizeof (struct yuarel));

	/* Scheme */
	url->scheme = u;
	u = strchr(u, ':');
	if (NULL == u || url->scheme == u) {
		return -1;
	}
	*(u++) = '\0'; // Replace ':' with NULL

	/* Forward to after // */
	while ('/' == *u) u++;

	/* Host */
	if ('\0' == *u) {
		return -1;
	}
	url->host = u;

	/* (Fragment) */
	u = strchr(u, '#');
	if (NULL != u) {
		*(u++) = '\0';
		url->fragment = u;
	}

	/* (Query) */
	u = strchr(url->host, '?');
	if (NULL != u && (!url->fragment || u < url->fragment)) {
		*(u++) = '\0';
		url->query = u;
	}

	/* (Path) */
	u = strchr(url->host, '/');
	if (NULL != u && (!url->query || u < url->query) && (!url->fragment || u < url->fragment)) {
		*(u++) = '\0';
		url->path = u;
	}

	/* (Port) */
	u = strchr(url->host, ':');
	if (NULL != u && (!url->query || u < url->query) && (!url->path || u < url->path) && (!url->fragment || u < url->fragment)) {
		*(u++) = '\0';
		if ('\0' == *u) {
			return -1;
		}

		if (url->path) {
			url->port = natoi(u, url->path - u - 1);
		} else {
			url->port = atoi(u);
		}
	}

	/* Check that host is not empty */
	if ('\0' == *(url->host)) {
		return -1;
	}

	return 0;
}

/**
 * Split a path into several strings.
 *
 * No data is copied, the slashed are used as null terminators and then
 * pointers to each path part will be stored in **parts. Double slashes will be
 * treated as one.
 *
 * *path:     the path to split.
 * **parts:   a pointer to an array of (char *) where to store the result.
 * max_parts: max number of parts to parse.
 */
int
yuarel_split_path(char *path, char **parts, int max_parts)
{
	int i = 0;

	do {
		/* Forward to after slashes */
		while ('/' == *path) path++;

		if ('\0' == *path) {
			break;
		}

		parts[i++] = path;

		if ((path = strchr(path, '/')) == NULL) {
			break;
		}

		*(path++) = '\0';
	} while (i < max_parts);

	return i;
}

int
yuarel_parse_query(char *query, char delimiter, struct yuarel_param *params, int max_params)
{
	int i = 0;

	if (NULL == query || '\0' == *query) {
		return -1;
	}

	params[i++].key = query;
	while (i < max_params && NULL != (query = strchr(query, delimiter))) {
		*query = '\0';
		params[i].key = ++query;
		params[i].val = NULL;

		/* Go back and split previous param */
		if (i > 0) {
			if (NULL != (params[i - 1].val = strchr(params[i - 1].key, '='))) {
				*(params[i - 1].val)++ = '\0';
			}
		}
		i++;
	}

	/* Go back and split last param */
	if (NULL != (params[i - 1].val = strchr(params[i - 1].key, '='))) {
		*(params[i - 1].val)++ = '\0';
	}

	return i;
}
