/* Copyright (C) 2013 the GSS-PROXY contributors, see COPYING for license */

#ifndef _GP_XDR_H_
#define _GP_XDR_H_

#include "gssrpc/rpc.h"

#define xdr_u_quad_t gp_xdr_uint64_t

bool_t gp_xdr_uint64_t(XDR *xdrs, uint64_t *objp);

#endif /* _GP_XDR_H_ */
