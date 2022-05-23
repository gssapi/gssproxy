/* Copyright (C) 2022 the GSS-PROXY contributors, see COPYING for license */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

char *srv_args[] = {
    "./gssproxy",
    "-u", "-i",
    "-s", "./testdir/userproxytest.sock",
    "--idle-timeout=3"
};

int mock_activation_sockets(void)
{
    struct sockaddr_un addr = {
        .sun_family = AF_UNIX,
        .sun_path = "./testdir/userproxytest.sock",
    };
    int fd;
    int ret;

    unlink(addr.sun_path);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) return -1;

    ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1) return -1;

    ret = listen(fd, 1);
    if (ret == -1) return -1;

    return 0;
}

int mock_activation_environment(void)
{
    char *onestr = "1";
    char *pidstr;
    int ret;

    ret = asprintf(&pidstr, "%u", (unsigned)getpid());
    if (ret == -1) return -1;

    setenv("LISTEN_PID", pidstr, 1);
    setenv("LISTEN_FDS", onestr, 1);

    free(pidstr);
    return 0;
}

int main(int argc, const char *main_argv[])
{
    pid_t proxy, w;
    int ret;

    fprintf(stderr, "Test userproxy mode: ");

    ret = mock_activation_sockets();
    if (ret) return -1;

    proxy = fork();
    if (proxy == -1) return -1;

    if (proxy == 0) {
        ret = mock_activation_environment();
        if (ret) return -1;

        execv("./gssproxy", srv_args);
        return -1;
    }

    sleep(6);

    w = waitpid(-1, &ret, WNOHANG);
    if (w != proxy || ret != 0) {
        fprintf(stderr, "FAIL\n");
        fflush(stderr);
        return -1;
    }

    fprintf(stderr, "SUCCESS\n");
    fflush(stderr);
    return 0;
}
