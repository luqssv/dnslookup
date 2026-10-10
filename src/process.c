#define _GNU_SOURCE

#include "dnslookup.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int run_external_capture(char *const argv[], int show_output)
{
    int p[2];
    if (pipe(p) < 0) return -1;

    pid_t pid = fork();
    if (pid < 0) {
        close(p[0]);
        close(p[1]);
        return -1;
    }

    if (pid == 0) {
        close(p[0]);
        if (show_output) {
            close(p[1]);
            execvp(argv[0], argv);
            _exit(127);
        }
        dup2(p[1], STDOUT_FILENO);
        dup2(p[1], STDERR_FILENO);
        close(p[1]);
        execvp(argv[0], argv);
        _exit(127);
    }

    close(p[1]);
    if (!show_output) {
        char b[4096];
        ssize_t n;
        while ((n = read(p[0], b, sizeof(b))) > 0)
            fwrite(b, 1, (size_t)n, stdout);
    }
    close(p[0]);

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}