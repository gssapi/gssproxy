/* Copyright (C) 2013 the GSS-PROXY contributors, see COPYING for license */

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
