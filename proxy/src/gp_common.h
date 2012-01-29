/*
   GSS-PROXY

   Copyright (C) 2011 Red Hat, Inc.
   Copyright (C) 2011 Simo Sorce <simo.sorce@redhat.com>

   Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and associated documentation files (the "Software"),
   to deal in the Software without restriction, including without limitation
   the rights to use, copy, modify, merge, publish, distribute, sublicense,
   and/or sell copies of the Software, and to permit persons to whom the
   Software is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
   THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
   FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
   DEALINGS IN THE SOFTWARE.
*/

#ifndef _GP_COMMON_H_
#define _GP_COMMON_H_

/* add element to list head */
#define LIST_ADD(list, elem) do { \
    elem->prev = NULL; \
    elem->next = list; \
    if (list) { \
        list->prev = elem; \
    } \
    list = elem; \
} while (0)

/* remove element from list */
#define LIST_DEL(list, elem) do { \
    if (elem->next) { \
        elem->next->prev = elem->prev; \
    } \
    if (elem->prev) { \
        elem->prev->next = elem->next; \
    } \
    if (list == elem) { \
        list = elem->next; \
    } \
    elem->prev = NULL; \
    elem->next = NULL; \
} while (0)

/* max out at 1MB for now */
#define MAX_RPC_SIZE 1024*1024

#endif /* _GP_COMMON_H_ */
