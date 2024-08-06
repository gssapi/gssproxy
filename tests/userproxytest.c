/* Copyright (C) 2022 the GSS-PROXY contributors, see COPYING for license */

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

char *srv_args[] = {
    "./gssproxy",
    "-u", "-i",
    "-d", "--debug-level=1",
    "-s", "./testdir/userproxytest.sock",
    "--idle-timeout=3",
    NULL
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
    if (fd == -1) {
        ret = -1;
        goto done;
    }

    ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == -1) goto done;

    ret = listen(fd, 1);
    if (ret == -1) goto done;

done:
    if (ret == -1) close(fd);
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

int wait_and_check_output(int outfd, int timeout)
{
    struct {
        const char *match;
        bool matched;
    } checks[] = {
        { "Initialization complete.", false },
        { "Terminating, after idling", false },
        { NULL, true }
    };
    time_t start = time(NULL);
    time_t now = start;
    useconds_t interval = 100 * 1000; /* 100 msec */
    char outbuf[1024];
    char *line;
    FILE *out = NULL;
    int err, ret = -1;

    /* make pipe non blocking */
    err = fcntl(outfd, F_SETFL, O_NONBLOCK);
    if (err) goto done;

    out = fdopen(outfd, "r");
    if (!out) goto done;

    while (now < start + timeout) {
        err = usleep(interval);
        if (err) goto done;

        line = fgets(outbuf, 1023, out);
        if (line) {
            for (int i = 0; checks[i].match != NULL; i++) {
                if (strstr(line, checks[i].match)) {
                    checks[i].matched = true;
                }
            }
        }

        now = time(NULL);
    }

    for (int i = 0; checks[i].match != NULL; i++) {
        if (checks[i].matched == false) goto done;
    }

    ret = 0;

done:
    if (out) fclose(out);
    return ret;
}

int child(int outpipe[])
{
    int ret;

    ret = mock_activation_environment();
    if (ret) exit(EXIT_FAILURE);

    close(outpipe[0]);
    ret = dup2(outpipe[1], 2);
    if (ret == -1) exit(EXIT_FAILURE);

    execv("./gssproxy", srv_args);
    exit(EXIT_FAILURE);
}

int main(int argc, const char *main_argv[])
{
    pid_t proxy, w;
    int outpipe[2];
    int ret;

    fprintf(stderr, "Test userproxy mode: ");

    ret = mock_activation_sockets();
    if (ret) {
        ret = EXIT_FAILURE;
        goto done;
    }

    ret = pipe(outpipe);
    if (ret) {
        ret = EXIT_FAILURE;
        goto done;
    }

    proxy = fork();
    if (proxy == -1) {
        ret = EXIT_FAILURE;
        goto done;
    }

    if (proxy == 0) {
        child(outpipe);
    }

    close(outpipe[1]);

    ret = wait_and_check_output(outpipe[0], 6);
    if (ret) {
        ret = EXIT_FAILURE;
        goto done;
    }

    w = waitpid(-1, &ret, WNOHANG);
    if (w != proxy || ret != 0) {
        ret = EXIT_FAILURE;
        goto done;
    }

    ret = 0;

done:
    if (ret) {
        fprintf(stderr, "FAIL\n");
        fflush(stderr);
        return ret;
    }

    fprintf(stderr, "SUCCESS\n");
    fflush(stderr);
    return 0;
}
