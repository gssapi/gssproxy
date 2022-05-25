/* Copyright (C) 2022 the GSS-PROXY contributors, see COPYING for license */

#include "config.h"
#include "gp_proxy.h"
#include <time.h>

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

void gp_activity_accounting(struct gssproxy_ctx *gpctx,
                            ssize_t rb, ssize_t wb)
{
    time_t now = time(NULL);

    if (rb) {
        /* Gssproxy received some request */
        gpctx->readstats += rb;
        GPDEBUGN(GP_INFO_DEBUG_LVL, "Total received bytes: %ld\n",
                 (long)gpctx->readstats);

        /* receiving bytes is also a sign of activity,
         * reset idle event */
        idle_handler(gpctx);

        GPDEBUGN(GP_INFO_DEBUG_LVL, "Idle for: %ld seconds\n",
                 now - gpctx->last_activity);
        gpctx->last_activity = now;
    }

    if (wb) {
        gpctx->writestats += wb;
        GPDEBUGN(GP_INFO_DEBUG_LVL, "Total sent bytes: %ld\n",
                 (long)gpctx->writestats);

        /* sending bytes is also a sign of activity, but we send
         * bytes only in response to requests and this is already
         * captured by a previous read event, just update the
         * last_activity counter to have a more precise info messgae
         * on the following read */
        gpctx->last_activity = now;
    }
}
