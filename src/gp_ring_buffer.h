/*
   GSS-PROXY

   Copyright (C) 2012 Red Hat, Inc.
   Copyright (C) 2012 Guenther Deschner <guenther.deschner@redhat.com>

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

#ifndef _GP_RING_BUFFER_H_
#define _GP_RING_BUFFER_H_

#include <gssapi/gssapi.h>

uint32_t gp_init_ring_buffer(uint32_t *min,
                             const char *name,
                             uint32_t ring_size,
                             struct gp_ring_buffer **buffer_out);
void gp_free_ring_buffer(struct gp_ring_buffer *buffer);

#endif /* _GP_RING_BUFFER_H_ */
