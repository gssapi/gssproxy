/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "rpcgen/gss_proxy.h"

bool_t
xdr_utf8string (XDR *xdrs, utf8string *objp)
{
	 if (!xdr_bytes (xdrs, (char **)&objp->utf8string_val, (u_int *) &objp->utf8string_len, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_octet_string (XDR *xdrs, octet_string *objp)
{
	 if (!xdr_bytes (xdrs, (char **)&objp->octet_string_val, (u_int *) &objp->octet_string_len, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_uint64 (XDR *xdrs, gssx_uint64 *objp)
{
	 if (!xdr_u_quad_t (xdrs, objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_qop (XDR *xdrs, gssx_qop *objp)
{
	 if (!xdr_u_quad_t (xdrs, objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_buffer (XDR *xdrs, gssx_buffer *objp)
{
	 if (!xdr_octet_string (xdrs, objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_OID (XDR *xdrs, gssx_OID *objp)
{
	 if (!xdr_octet_string (xdrs, objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_OID_set (XDR *xdrs, gssx_OID_set *objp)
{
	 if (!xdr_array (xdrs, (char **)&objp->gssx_OID_set_val, (u_int *) &objp->gssx_OID_set_len, ~0,
		sizeof (gssx_OID), (xdrproc_t) xdr_gssx_OID))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_cred_usage (XDR *xdrs, gssx_cred_usage *objp)
{
	 if (!xdr_enum (xdrs, (enum_t *) objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_time (XDR *xdrs, gssx_time *objp)
{
	 if (!xdr_u_quad_t (xdrs, objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_ext_id (XDR *xdrs, gssx_ext_id *objp)
{
	 if (!xdr_enum (xdrs, (enum_t *) objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_typed_hole (XDR *xdrs, gssx_typed_hole *objp)
{
	 if (!xdr_gssx_ext_id (xdrs, &objp->ext_type))
		 return FALSE;
	 if (!xdr_octet_string (xdrs, &objp->ext_data))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_mech_attr (XDR *xdrs, gssx_mech_attr *objp)
{
	 if (!xdr_gssx_OID (xdrs, &objp->attr))
		 return FALSE;
	 if (!xdr_gssx_buffer (xdrs, &objp->name))
		 return FALSE;
	 if (!xdr_gssx_buffer (xdrs, &objp->short_desc))
		 return FALSE;
	 if (!xdr_gssx_buffer (xdrs, &objp->long_desc))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_mech_info (XDR *xdrs, gssx_mech_info *objp)
{
	 if (!xdr_gssx_OID (xdrs, &objp->mech))
		 return FALSE;
	 if (!xdr_gssx_OID_set (xdrs, &objp->name_types))
		 return FALSE;
	 if (!xdr_gssx_OID_set (xdrs, &objp->mech_attrs))
		 return FALSE;
	 if (!xdr_gssx_OID_set (xdrs, &objp->known_mech_attrs))
		 return FALSE;
	 if (!xdr_gssx_OID_set (xdrs, &objp->cred_options))
		 return FALSE;
	 if (!xdr_gssx_OID_set (xdrs, &objp->sec_ctx_options))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->provider_names.provider_names_val, (u_int *) &objp->provider_names.provider_names_len, ~0,
		sizeof (utf8string), (xdrproc_t) xdr_utf8string))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->provider_paths.provider_paths_val, (u_int *) &objp->provider_paths.provider_paths_len, ~0,
		sizeof (utf8string), (xdrproc_t) xdr_utf8string))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_name_attr (XDR *xdrs, gssx_name_attr *objp)
{
	 if (!xdr_gssx_buffer (xdrs, &objp->attr))
		 return FALSE;
	 if (!xdr_gssx_buffer (xdrs, &objp->value))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_option (XDR *xdrs, gssx_option *objp)
{
	 if (!xdr_gssx_OID (xdrs, &objp->option))
		 return FALSE;
	 if (!xdr_gssx_buffer (xdrs, &objp->value))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_status (XDR *xdrs, gssx_status *objp)
{
	 if (!xdr_gssx_uint64 (xdrs, &objp->major_status))
		 return FALSE;
	 if (!xdr_gssx_OID (xdrs, &objp->mech))
		 return FALSE;
	 if (!xdr_gssx_uint64 (xdrs, &objp->minor_status))
		 return FALSE;
	 if (!xdr_utf8string (xdrs, &objp->major_status_string))
		 return FALSE;
	 if (!xdr_utf8string (xdrs, &objp->minor_status_string))
		 return FALSE;
	 if (!xdr_octet_string (xdrs, &objp->server_ctx))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_call_ctx (XDR *xdrs, gssx_call_ctx *objp)
{
	 if (!xdr_utf8string (xdrs, &objp->locale))
		 return FALSE;
	 if (!xdr_octet_string (xdrs, &objp->server_ctx))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_name (XDR *xdrs, gssx_name *objp)
{
	 if (!xdr_pointer (xdrs, (char **)&objp->display_name, sizeof (gssx_buffer), (xdrproc_t) xdr_gssx_buffer))
		 return FALSE;
	 if (!xdr_gssx_OID (xdrs, &objp->name_type))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->exported_name.exported_name_val, (u_int *) &objp->exported_name.exported_name_len, ~0,
		sizeof (gssx_buffer), (xdrproc_t) xdr_gssx_buffer))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->exported_composite_name.exported_composite_name_val, (u_int *) &objp->exported_composite_name.exported_composite_name_len, ~0,
		sizeof (gssx_buffer), (xdrproc_t) xdr_gssx_buffer))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->name_attributes.name_attributes_val, (u_int *) &objp->name_attributes.name_attributes_len, ~0,
		sizeof (gssx_name_attr), (xdrproc_t) xdr_gssx_name_attr))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_cred_element (XDR *xdrs, gssx_cred_element *objp)
{
	 if (!xdr_gssx_name (xdrs, &objp->MN))
		 return FALSE;
	 if (!xdr_gssx_OID (xdrs, &objp->mech))
		 return FALSE;
	 if (!xdr_gssx_cred_usage (xdrs, &objp->cred_usage))
		 return FALSE;
	 if (!xdr_gssx_time (xdrs, &objp->initiator_time_rec))
		 return FALSE;
	 if (!xdr_gssx_time (xdrs, &objp->acceptor_time_rec))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->cred_options.cred_options_val, (u_int *) &objp->cred_options.cred_options_len, ~0,
		sizeof (gssx_option), (xdrproc_t) xdr_gssx_option))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_cred (XDR *xdrs, gssx_cred *objp)
{
	 if (!xdr_gssx_name (xdrs, &objp->desired_name))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->elements.elements_val, (u_int *) &objp->elements.elements_len, ~0,
		sizeof (gssx_cred_element), (xdrproc_t) xdr_gssx_cred_element))
		 return FALSE;
	 if (!xdr_octet_string (xdrs, &objp->cred_handle_reference))
		 return FALSE;
	 if (!xdr_bool (xdrs, &objp->needs_release))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_ctx (XDR *xdrs, gssx_ctx *objp)
{
	 if (!xdr_pointer (xdrs, (char **)&objp->exported_context_token, sizeof (gssx_buffer), (xdrproc_t) xdr_gssx_buffer))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->state, sizeof (octet_string), (xdrproc_t) xdr_octet_string))
		 return FALSE;
	 if (!xdr_bool (xdrs, &objp->needs_release))
		 return FALSE;
	 if (!xdr_gssx_OID (xdrs, &objp->mech))
		 return FALSE;
	 if (!xdr_gssx_name (xdrs, &objp->src_name))
		 return FALSE;
	 if (!xdr_gssx_name (xdrs, &objp->targ_name))
		 return FALSE;
	 if (!xdr_gssx_time (xdrs, &objp->lifetime))
		 return FALSE;
	 if (!xdr_gssx_uint64 (xdrs, &objp->ctx_flags))
		 return FALSE;
	 if (!xdr_bool (xdrs, &objp->locally_initiated))
		 return FALSE;
	 if (!xdr_bool (xdrs, &objp->open))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->context_options.context_options_val, (u_int *) &objp->context_options.context_options_len, ~0,
		sizeof (gssx_option), (xdrproc_t) xdr_gssx_option))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_handle_type (XDR *xdrs, gssx_handle_type *objp)
{
	 if (!xdr_enum (xdrs, (enum_t *) objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_handle (XDR *xdrs, gssx_handle *objp)
{
	 if (!xdr_gssx_handle_type (xdrs, &objp->handle_type))
		 return FALSE;
	switch (objp->handle_type) {
	case GSSX_C_HANDLE_CRED:
		 if (!xdr_array (xdrs, (char **)&objp->gssx_handle_u.cred_info.cred_info_val, (u_int *) &objp->gssx_handle_u.cred_info.cred_info_len, ~0,
			sizeof (gssx_cred), (xdrproc_t) xdr_gssx_cred))
			 return FALSE;
		break;
	case GSSX_C_HANDLE_SEC_CTX:
		 if (!xdr_gssx_ctx (xdrs, &objp->gssx_handle_u.sec_ctx_info))
			 return FALSE;
		break;
	default:
		 if (!xdr_octet_string (xdrs, &objp->gssx_handle_u.extensions))
			 return FALSE;
		break;
	}
	return TRUE;
}

bool_t
xdr_gssx_cb (XDR *xdrs, gssx_cb *objp)
{
	 if (!xdr_gssx_uint64 (xdrs, &objp->initiator_addrtype))
		 return FALSE;
	 if (!xdr_gssx_buffer (xdrs, &objp->initiator_address))
		 return FALSE;
	 if (!xdr_gssx_uint64 (xdrs, &objp->acceptor_addrtype))
		 return FALSE;
	 if (!xdr_gssx_buffer (xdrs, &objp->acceptor_address))
		 return FALSE;
	 if (!xdr_gssx_buffer (xdrs, &objp->application_data))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_arg_release_handle (XDR *xdrs, gssx_arg_release_handle *objp)
{
	 if (!xdr_gssx_call_ctx (xdrs, &objp->call_ctx))
		 return FALSE;
	 if (!xdr_gssx_handle (xdrs, &objp->cred_handle))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_res_release_handle (XDR *xdrs, gssx_res_release_handle *objp)
{
	 if (!xdr_gssx_status (xdrs, &objp->status))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_arg_indicate_mechs (XDR *xdrs, gssx_arg_indicate_mechs *objp)
{
	 if (!xdr_gssx_call_ctx (xdrs, &objp->call_ctx))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_res_indicate_mechs (XDR *xdrs, gssx_res_indicate_mechs *objp)
{
	 if (!xdr_gssx_status (xdrs, &objp->status))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->mechs.mechs_val, (u_int *) &objp->mechs.mechs_len, ~0,
		sizeof (gssx_mech_info), (xdrproc_t) xdr_gssx_mech_info))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->mech_attr_descs.mech_attr_descs_val, (u_int *) &objp->mech_attr_descs.mech_attr_descs_len, ~0,
		sizeof (gssx_mech_attr), (xdrproc_t) xdr_gssx_mech_attr))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->supported_extensions.supported_extensions_val, (u_int *) &objp->supported_extensions.supported_extensions_len, ~0,
		sizeof (gssx_ext_id), (xdrproc_t) xdr_gssx_ext_id))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_arg_import_and_canon_name (XDR *xdrs, gssx_arg_import_and_canon_name *objp)
{
	 if (!xdr_gssx_call_ctx (xdrs, &objp->call_ctx))
		 return FALSE;
	 if (!xdr_gssx_name (xdrs, &objp->input_name))
		 return FALSE;
	 if (!xdr_gssx_OID (xdrs, &objp->mech))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->name_attributes.name_attributes_val, (u_int *) &objp->name_attributes.name_attributes_len, ~0,
		sizeof (gssx_name_attr), (xdrproc_t) xdr_gssx_name_attr))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_res_import_and_canon_name (XDR *xdrs, gssx_res_import_and_canon_name *objp)
{
	 if (!xdr_gssx_status (xdrs, &objp->status))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->output_name, sizeof (gssx_name), (xdrproc_t) xdr_gssx_name))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_arg_get_call_context (XDR *xdrs, gssx_arg_get_call_context *objp)
{
	 if (!xdr_gssx_call_ctx (xdrs, &objp->call_ctx))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_res_get_call_context (XDR *xdrs, gssx_res_get_call_context *objp)
{
	 if (!xdr_gssx_status (xdrs, &objp->status))
		 return FALSE;
	 if (!xdr_octet_string (xdrs, &objp->server_call_ctx))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_arg_acquire_cred (XDR *xdrs, gssx_arg_acquire_cred *objp)
{
	 if (!xdr_gssx_call_ctx (xdrs, &objp->call_ctx))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->cred_options.cred_options_val, (u_int *) &objp->cred_options.cred_options_len, ~0,
		sizeof (gssx_option), (xdrproc_t) xdr_gssx_option))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->input_cred_handle, sizeof (gssx_cred), (xdrproc_t) xdr_gssx_cred))
		 return FALSE;
	 if (!xdr_bool (xdrs, &objp->add_cred_to_input_handle))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->desired_name, sizeof (gssx_name), (xdrproc_t) xdr_gssx_name))
		 return FALSE;
	 if (!xdr_gssx_time (xdrs, &objp->time_req))
		 return FALSE;
	 if (!xdr_gssx_OID_set (xdrs, &objp->desired_mechs))
		 return FALSE;
	 if (!xdr_gssx_cred_usage (xdrs, &objp->cred_usage))
		 return FALSE;
	 if (!xdr_gssx_time (xdrs, &objp->initiator_time_req))
		 return FALSE;
	 if (!xdr_gssx_time (xdrs, &objp->acceptor_time_req))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_res_acquire_cred (XDR *xdrs, gssx_res_acquire_cred *objp)
{
	 if (!xdr_gssx_status (xdrs, &objp->status))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->output_cred_handle, sizeof (gssx_cred), (xdrproc_t) xdr_gssx_cred))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_arg_export_cred (XDR *xdrs, gssx_arg_export_cred *objp)
{
	 if (!xdr_gssx_call_ctx (xdrs, &objp->call_ctx))
		 return FALSE;
	 if (!xdr_gssx_cred (xdrs, &objp->input_cred_handle))
		 return FALSE;
	 if (!xdr_gssx_cred_usage (xdrs, &objp->cred_usage))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_res_export_cred (XDR *xdrs, gssx_res_export_cred *objp)
{
	 if (!xdr_gssx_status (xdrs, &objp->status))
		 return FALSE;
	 if (!xdr_gssx_cred_usage (xdrs, &objp->usage_exported))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->exported_handle, sizeof (octet_string), (xdrproc_t) xdr_octet_string))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_arg_import_cred (XDR *xdrs, gssx_arg_import_cred *objp)
{
	 if (!xdr_gssx_call_ctx (xdrs, &objp->call_ctx))
		 return FALSE;
	 if (!xdr_octet_string (xdrs, &objp->exported_handle))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_res_import_cred (XDR *xdrs, gssx_res_import_cred *objp)
{
	 if (!xdr_gssx_status (xdrs, &objp->status))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->output_cred_handle, sizeof (gssx_cred), (xdrproc_t) xdr_gssx_cred))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_arg_store_cred (XDR *xdrs, gssx_arg_store_cred *objp)
{
	 if (!xdr_gssx_call_ctx (xdrs, &objp->call_ctx))
		 return FALSE;
	 if (!xdr_gssx_cred (xdrs, &objp->input_cred_handle))
		 return FALSE;
	 if (!xdr_gssx_cred_usage (xdrs, &objp->cred_usage))
		 return FALSE;
	 if (!xdr_gssx_OID (xdrs, &objp->desired_mech))
		 return FALSE;
	 if (!xdr_bool (xdrs, &objp->overwrite_cred))
		 return FALSE;
	 if (!xdr_bool (xdrs, &objp->default_cred))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_res_store_cred (XDR *xdrs, gssx_res_store_cred *objp)
{
	 if (!xdr_gssx_status (xdrs, &objp->status))
		 return FALSE;
	 if (!xdr_gssx_OID_set (xdrs, &objp->elements_stored))
		 return FALSE;
	 if (!xdr_gssx_cred_usage (xdrs, &objp->cred_usage_stored))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_arg_init_sec_context (XDR *xdrs, gssx_arg_init_sec_context *objp)
{
	 if (!xdr_gssx_call_ctx (xdrs, &objp->call_ctx))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->context_options.context_options_val, (u_int *) &objp->context_options.context_options_len, ~0,
		sizeof (gssx_option), (xdrproc_t) xdr_gssx_option))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->context_handle, sizeof (gssx_ctx), (xdrproc_t) xdr_gssx_ctx))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->cred_handle, sizeof (gssx_cred), (xdrproc_t) xdr_gssx_cred))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->target_name, sizeof (gssx_name), (xdrproc_t) xdr_gssx_name))
		 return FALSE;
	 if (!xdr_gssx_OID (xdrs, &objp->mech_type))
		 return FALSE;
	 if (!xdr_gssx_uint64 (xdrs, &objp->req_flags))
		 return FALSE;
	 if (!xdr_gssx_time (xdrs, &objp->time_req))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->input_cb, sizeof (gssx_cb), (xdrproc_t) xdr_gssx_cb))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->input_token, sizeof (gssx_buffer), (xdrproc_t) xdr_gssx_buffer))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_res_init_sec_context (XDR *xdrs, gssx_res_init_sec_context *objp)
{
	 if (!xdr_gssx_status (xdrs, &objp->status))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->context_handle, sizeof (gssx_ctx), (xdrproc_t) xdr_gssx_ctx))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->output_token, sizeof (gssx_buffer), (xdrproc_t) xdr_gssx_buffer))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_arg_accept_sec_context (XDR *xdrs, gssx_arg_accept_sec_context *objp)
{
	 if (!xdr_gssx_call_ctx (xdrs, &objp->call_ctx))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->context_options.context_options_val, (u_int *) &objp->context_options.context_options_len, ~0,
		sizeof (gssx_option), (xdrproc_t) xdr_gssx_option))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->context_handle, sizeof (gssx_ctx), (xdrproc_t) xdr_gssx_ctx))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->cred_handle, sizeof (gssx_cred), (xdrproc_t) xdr_gssx_cred))
		 return FALSE;
	 if (!xdr_gssx_buffer (xdrs, &objp->input_token))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->input_cb, sizeof (gssx_cb), (xdrproc_t) xdr_gssx_cb))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_res_accept_sec_context (XDR *xdrs, gssx_res_accept_sec_context *objp)
{
	 if (!xdr_gssx_status (xdrs, &objp->status))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->context_handle, sizeof (gssx_ctx), (xdrproc_t) xdr_gssx_ctx))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->output_token, sizeof (gssx_buffer), (xdrproc_t) xdr_gssx_buffer))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->delegated_cred_handle, sizeof (gssx_cred), (xdrproc_t) xdr_gssx_cred))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->extensions.extensions_val, (u_int *) &objp->extensions.extensions_len, ~0,
		sizeof (gssx_typed_hole), (xdrproc_t) xdr_gssx_typed_hole))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_arg_get_mic (XDR *xdrs, gssx_arg_get_mic *objp)
{
	 if (!xdr_gssx_call_ctx (xdrs, &objp->call_ctx))
		 return FALSE;
	 if (!xdr_gssx_ctx (xdrs, &objp->context_handle))
		 return FALSE;
	 if (!xdr_gssx_qop (xdrs, &objp->qop_req))
		 return FALSE;
	 if (!xdr_gssx_buffer (xdrs, &objp->message_buffer))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_res_get_mic (XDR *xdrs, gssx_res_get_mic *objp)
{
	 if (!xdr_gssx_status (xdrs, &objp->status))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->context_handle, sizeof (gssx_ctx), (xdrproc_t) xdr_gssx_ctx))
		 return FALSE;
	 if (!xdr_gssx_buffer (xdrs, &objp->token_buffer))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->qop_state, sizeof (gssx_qop), (xdrproc_t) xdr_gssx_qop))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_arg_verify_mic (XDR *xdrs, gssx_arg_verify_mic *objp)
{
	 if (!xdr_gssx_call_ctx (xdrs, &objp->call_ctx))
		 return FALSE;
	 if (!xdr_gssx_ctx (xdrs, &objp->context_handle))
		 return FALSE;
	 if (!xdr_gssx_buffer (xdrs, &objp->message_buffer))
		 return FALSE;
	 if (!xdr_gssx_buffer (xdrs, &objp->token_buffer))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_res_verify_mic (XDR *xdrs, gssx_res_verify_mic *objp)
{
	 if (!xdr_gssx_status (xdrs, &objp->status))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->context_handle, sizeof (gssx_ctx), (xdrproc_t) xdr_gssx_ctx))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->qop_state, sizeof (gssx_qop), (xdrproc_t) xdr_gssx_qop))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_arg_wrap (XDR *xdrs, gssx_arg_wrap *objp)
{
	 if (!xdr_gssx_call_ctx (xdrs, &objp->call_ctx))
		 return FALSE;
	 if (!xdr_gssx_ctx (xdrs, &objp->context_handle))
		 return FALSE;
	 if (!xdr_bool (xdrs, &objp->conf_req))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->message_buffer.message_buffer_val, (u_int *) &objp->message_buffer.message_buffer_len, ~0,
		sizeof (gssx_buffer), (xdrproc_t) xdr_gssx_buffer))
		 return FALSE;
	 if (!xdr_gssx_qop (xdrs, &objp->qop_state))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_res_wrap (XDR *xdrs, gssx_res_wrap *objp)
{
	 if (!xdr_gssx_status (xdrs, &objp->status))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->context_handle, sizeof (gssx_ctx), (xdrproc_t) xdr_gssx_ctx))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->token_buffer.token_buffer_val, (u_int *) &objp->token_buffer.token_buffer_len, ~0,
		sizeof (gssx_buffer), (xdrproc_t) xdr_gssx_buffer))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->conf_state, sizeof (bool_t), (xdrproc_t) xdr_bool))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->qop_state, sizeof (gssx_qop), (xdrproc_t) xdr_gssx_qop))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_arg_unwrap (XDR *xdrs, gssx_arg_unwrap *objp)
{
	 if (!xdr_gssx_call_ctx (xdrs, &objp->call_ctx))
		 return FALSE;
	 if (!xdr_gssx_ctx (xdrs, &objp->context_handle))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->token_buffer.token_buffer_val, (u_int *) &objp->token_buffer.token_buffer_len, ~0,
		sizeof (gssx_buffer), (xdrproc_t) xdr_gssx_buffer))
		 return FALSE;
	 if (!xdr_gssx_qop (xdrs, &objp->qop_state))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_res_unwrap (XDR *xdrs, gssx_res_unwrap *objp)
{
	 if (!xdr_gssx_status (xdrs, &objp->status))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->context_handle, sizeof (gssx_ctx), (xdrproc_t) xdr_gssx_ctx))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->message_buffer.message_buffer_val, (u_int *) &objp->message_buffer.message_buffer_len, ~0,
		sizeof (gssx_buffer), (xdrproc_t) xdr_gssx_buffer))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->conf_state, sizeof (bool_t), (xdrproc_t) xdr_bool))
		 return FALSE;
	 if (!xdr_pointer (xdrs, (char **)&objp->qop_state, sizeof (gssx_qop), (xdrproc_t) xdr_gssx_qop))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_arg_wrap_size_limit (XDR *xdrs, gssx_arg_wrap_size_limit *objp)
{
	 if (!xdr_gssx_call_ctx (xdrs, &objp->call_ctx))
		 return FALSE;
	 if (!xdr_gssx_ctx (xdrs, &objp->context_handle))
		 return FALSE;
	 if (!xdr_bool (xdrs, &objp->conf_req))
		 return FALSE;
	 if (!xdr_gssx_qop (xdrs, &objp->qop_state))
		 return FALSE;
	 if (!xdr_gssx_uint64 (xdrs, &objp->req_output_size))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_gssx_res_wrap_size_limit (XDR *xdrs, gssx_res_wrap_size_limit *objp)
{
	 if (!xdr_gssx_status (xdrs, &objp->status))
		 return FALSE;
	 if (!xdr_gssx_uint64 (xdrs, &objp->max_input_size))
		 return FALSE;
	return TRUE;
}
