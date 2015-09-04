/* Copyright (C) 2011 the GSS-PROXY contributors, see COPYING for license */

#ifndef _GP_CREDS_H_
#define _GP_CREDS_H_

#include "config.h"
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <gssapi/gssapi.h>

#define CRED_TYPE_NONE 0x00
#define CRED_TYPE_UNIX 0x01
#define CRED_TYPE_SELINUX 0x02

struct gp_creds {
    int type;
    struct ucred ucred;
};

#endif /* _GP_CREDS_H_ */
