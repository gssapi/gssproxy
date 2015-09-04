/* Copyright (C) 2011,2012 the GSS-PROXY contributors, see COPYING for license */

#ifndef _GSS_CONFIG_H_
#define _GSS_CONFIG_H_

struct gp_ini_context {
    void *private_data;
};

int gp_config_init(const char *config_file, const char *config_dir,
                   struct gp_ini_context *ctx);
int gp_config_get_string(struct gp_ini_context *ctx,
                         const char *secname,
                         const char *keyname,
                         const char **value);
int gp_config_get_string_array(struct gp_ini_context *ctx,
                               const char *secname,
                               const char *keyname,
                               int *num_values,
                               const char ***values);
int gp_config_get_int(struct gp_ini_context *ctx,
                      const char *secname,
                      const char *keyname,
                      int *value);
int gp_config_get_nsec(struct gp_ini_context *ctx);
char *gp_config_get_secname(struct gp_ini_context *ctx,
                            int i);
int gp_config_close(struct gp_ini_context *ctx);

#endif /* _GSS_CONFIG_H_ */
