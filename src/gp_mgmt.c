/* Copyright (C) 2022 the GSS-PROXY contributors, see COPYING for license */

#include "config.h"
#include "gp_proxy.h"

static void idle_terminate(verto_ctx *vctx, verto_ev *ev)
{
    struct gssproxy_ctx *gpctx = verto_get_private(ev);

    GPDEBUG("Terminating, after idling for %ld seconds!\n",
            (long)gpctx->term_timeout/1000);
    verto_break(vctx);
}

void idle_handler(struct gssproxy_ctx *gpctx)
{
    /* we've been called, this means some event just fired,
     * restart the timeout handler */

    if (gpctx->term_timeout == 0) {
        /* self termination is disabled */
        return;
    }

    verto_del(gpctx->term_ev);

    /* Add self-termination timeout */
    gpctx->term_ev = verto_add_timeout(gpctx->vctx, VERTO_EV_FLAG_NONE,
                                       idle_terminate, gpctx->term_timeout);
    if (!gpctx->term_ev) {
        GPDEBUG("Failed to register timeout event!\n");
    }
    verto_set_private(gpctx->term_ev, gpctx, NULL);
}


