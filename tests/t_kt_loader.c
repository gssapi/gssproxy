/* Copyright (C) 2026 the GSS-PROXY contributors, see COPYING for license */

/* A keytab_loader for the tests: "unseal" a keytab and write it to the
 * memfd gssproxy passes as file descriptor 3.
 *
 *   t_kt_loader SEALED [FAILFILE]
 *
 * SEALED is a keytab with every byte XORed with T_KT_SEAL_BYTE, so the file
 * itself is not a usable keytab and gssproxy only gets the keys through the
 * loader.  While FAILFILE exists the loader fails with status 75 (retry
 * later), as kuipa-unseal does when no server can unseal. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define T_KT_SEAL_BYTE 0x5a
#define LOADER_FD 3
#define EX_TEMPFAIL 75

int main(int argc, const char *argv[])
{
    unsigned char buf[4096];
    size_t len, off;
    ssize_t w;
    FILE *f;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s SEALED [FAILFILE]\n", argv[0]);
        return 1;
    }

    if (argc == 3 && access(argv[2], F_OK) == 0) {
        fprintf(stderr, "%s: %s exists, failing\n", argv[0], argv[2]);
        return EX_TEMPFAIL;
    }

    f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "%s: %s: %s\n", argv[0], argv[1], strerror(errno));
        return 1;
    }

    while ((len = fread(buf, 1, sizeof(buf), f)) > 0) {
        for (size_t i = 0; i < len; i++) {
            buf[i] ^= T_KT_SEAL_BYTE;
        }
        for (off = 0; off < len; off += w) {
            w = write(LOADER_FD, buf + off, len - off);
            if (w == -1) {
                if (errno == EINTR) {
                    w = 0;
                    continue;
                }
                fprintf(stderr, "%s: write: %s\n", argv[0], strerror(errno));
                fclose(f);
                return 1;
            }
        }
    }
    if (ferror(f)) {
        fprintf(stderr, "%s: %s: read error\n", argv[0], argv[1]);
        fclose(f);
        return 1;
    }

    fclose(f);
    return 0;
}
