/*
   GSS-PROXY

   Copyright (C) 2012 Red Hat, Inc.
   Copyright (C) 2012 Simo Sorce <simo.sorce@redhat.com>

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

#include "gss_plugin.h"

/* This will never be called, added only for completeness */
OM_uint32 gssi_indicate_mechs(OM_uint32 *minor_status, gss_OID_set *mech_set)
{
    GSSI_TRACE();
    *minor_status = 0;
    return GSS_S_FAILURE;
}

OM_uint32 gssi_inquire_names_for_mech(OM_uint32 *minor_status,
                                      gss_OID mech_type,
                                      gss_OID_set *mech_names)
{
    enum gpp_behavior behavior;
    OM_uint32 tmaj, tmin;
    OM_uint32 maj, min;

    GSSI_TRACE();

    behavior = gpp_get_behavior();
    tmaj = GSS_S_COMPLETE;
    tmin = 0;

    /* See if we should try local first */
    if (behavior == GPP_LOCAL_ONLY || behavior == GPP_LOCAL_FIRST) {

        maj = gss_inquire_names_for_mech(&min,
                                         gpp_special_mech(mech_type),
                                         mech_names);
        if (maj == GSS_S_COMPLETE || behavior == GPP_LOCAL_ONLY) {
            goto done;
        }

        /* not successful, save actual local error if remote fallback fails */
        tmaj = maj;
        tmin = min;
    }

    /* Then try with remote */
    if (behavior != GPP_LOCAL_ONLY) {

        maj = gpm_inquire_names_for_mech(&min, mech_type, mech_names);
        if (maj == GSS_S_COMPLETE || behavior == GPP_REMOTE_ONLY) {
            goto done;
        }

        /* So remote failed, but we can fallback to local, try that */
        maj = gss_inquire_names_for_mech(&min,
                                         gpp_special_mech(mech_type),
                                         mech_names);
    }

done:
    if (maj != GSS_S_COMPLETE && tmaj != GSS_S_COMPLETE) {
        maj = tmaj;
        min = tmin;
    }
    *minor_status = gpp_map_error(min);
    return maj;
}

OM_uint32 gssi_inquire_attrs_for_mech(OM_uint32 *minor_status,
                                      gss_OID mech,
                                      gss_OID_set *mech_attrs,
                                      gss_OID_set *known_mech_attrs)
{
    enum gpp_behavior behavior;
    OM_uint32 tmaj, tmin;
    OM_uint32 maj, min;

    GSSI_TRACE();

    behavior = gpp_get_behavior();
    tmaj = GSS_S_COMPLETE;
    tmin = 0;

    /* See if we should try local first */
    if (behavior == GPP_LOCAL_ONLY || behavior == GPP_LOCAL_FIRST) {

        maj = gss_inquire_attrs_for_mech(&min, gpp_special_mech(mech),
                                         mech_attrs, known_mech_attrs);
        if (maj == GSS_S_COMPLETE || behavior == GPP_LOCAL_ONLY) {
            goto done;
        }

        /* not successful, save actual local error if remote fallback fails */
        tmaj = maj;
        tmin = min;
    }

    /* Then try with remote */
    if (behavior != GPP_LOCAL_ONLY) {

        maj = gpm_inquire_attrs_for_mech(&min, mech,
                                         mech_attrs, known_mech_attrs);
        if (maj == GSS_S_COMPLETE || behavior == GPP_REMOTE_ONLY) {
            goto done;
        }

        /* So remote failed, but we can fallback to local, try that */
        maj = gss_inquire_attrs_for_mech(&min, gpp_special_mech(mech),
                                         mech_attrs, known_mech_attrs);
    }

done:
    if (maj != GSS_S_COMPLETE && tmaj != GSS_S_COMPLETE) {
        maj = tmaj;
        min = tmin;
    }
    *minor_status = gpp_map_error(min);
    return maj;
}

OM_uint32 gssi_inquire_saslname_for_mech(OM_uint32 *minor_status,
                                         const gss_OID desired_mech,
                                         gss_buffer_t sasl_mech_name,
                                         gss_buffer_t mech_name,
                                         gss_buffer_t mech_description)
{
    enum gpp_behavior behavior;
    OM_uint32 tmaj, tmin;
    OM_uint32 maj, min;

    GSSI_TRACE();

    behavior = gpp_get_behavior();
    tmaj = GSS_S_COMPLETE;
    tmin = 0;

    /* See if we should try local first */
    if (behavior == GPP_LOCAL_ONLY || behavior == GPP_LOCAL_FIRST) {

        maj = gss_inquire_saslname_for_mech(&min,
                                            gpp_special_mech(desired_mech),
                                            sasl_mech_name, mech_name,
                                            mech_description);
        if (maj == GSS_S_COMPLETE || behavior == GPP_LOCAL_ONLY) {
            goto done;
        }

        /* not successful, save actual local error if remote fallback fails */
        tmaj = maj;
        tmin = min;
    }

    /* Then try with remote */
    if (behavior != GPP_LOCAL_ONLY) {

        maj = gpm_inquire_saslname_for_mech(&min, desired_mech, sasl_mech_name,
                                            mech_name, mech_description);
        if (maj == GSS_S_COMPLETE || behavior == GPP_REMOTE_ONLY) {
            goto done;
        }

        /* So remote failed, but we can fallback to local, try that */
        maj = gss_inquire_saslname_for_mech(&min,
                                            gpp_special_mech(desired_mech),
                                            sasl_mech_name, mech_name,
                                            mech_description);
    }

done:
    if (maj != GSS_S_COMPLETE && tmaj != GSS_S_COMPLETE) {
        maj = tmaj;
        min = tmin;
    }
    *minor_status = gpp_map_error(min);
    return maj;
}

OM_uint32 gssi_inquire_mech_for_saslname(OM_uint32 *minor_status,
                                         const gss_buffer_t sasl_mech_name,
                                         gss_OID *mech_type)
{
    GSSI_TRACE();
    /* FIXME: How to call into mechglue ? */
    return GSS_S_UNAVAILABLE;
}
