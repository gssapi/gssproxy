/*
   GSS-PROXY

   Copyright (C) 2013 Red Hat, Inc.
   Copyright (C) 2013 Simo Sorce <simo@redhat.com>

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

#include "rpcgen/gp_xdr.h"

bool_t gp_xdr_uint64_t(XDR *xdrs, uint64_t *objp)
{
    uint32_t h;
    uint32_t l;

    switch(xdrs->x_op) {
    case XDR_ENCODE:
        h = (uint32_t)((*objp) >> 32);
        l = (uint32_t)(*objp);
        if (!xdr_u_int32(xdrs, &h) || !xdr_u_int32(xdrs, &l)) {
            return FALSE;
        }
        return TRUE;
    case XDR_DECODE:
        if (!xdr_u_int32(xdrs, &h) || !xdr_u_int32(xdrs, &l)) {
            return FALSE;
        }
        *objp = (((uint64_t)h) << 32) | l;
        return TRUE;
    case XDR_FREE:
        return TRUE;
    default:
        return FALSE;
    }
}
