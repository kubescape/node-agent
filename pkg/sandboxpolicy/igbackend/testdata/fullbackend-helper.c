// Disposable integration fixture, not production agent code.
// Build statically and install this binary as /probe/init, /probe/role and
// /probe/target-0 .. /probe/target-12 in the immutable image layer.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int device_probe(const char *name) {
    int fd = open(name, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd >= 0) { close(fd); return 0; }
    return errno == EPERM ? 77 : 78;
}

static int execute(const char *path, int chain) {
    int input[2];
    if (pipe2(input, O_CLOEXEC) != 0) return 90;
    pid_t child = fork();
    if (child < 0) { close(input[0]); close(input[1]); return 91; }
    if (child == 0) {
        close(input[1]);
        if (input[0] == STDIN_FILENO) {
            if (fcntl(input[0], F_SETFD, 0) < 0) _exit(92);
        } else {
            if (dup2(input[0], STDIN_FILENO) < 0) _exit(92);
            close(input[0]);
        }
        char *args[] = {(char *)path, chain ? "--chain" : "--target", "--token=ok", NULL};
        execv(path, args);
        _exit(errno == EPERM ? 77 : 78);
    }
    close(input[0]);
    close(input[1]);
    int status;
    while (waitpid(child, &status, 0) < 0) if (errno != EINTR) return 93;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 94;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--target") == 0) return 0;
    if (argc > 1 && strcmp(argv[1], "--chain") == 0)
        return execute("/probe/target-12", 0);
    if (argc != 2 || strcmp(argv[1], "--serve") != 0) return 95;
    if (mkdir("/fixture-control", 0700) != 0 && errno != EEXIST) return 96;
    if (mkfifo("/fixture-control/request", 0600) != 0 && errno != EEXIST) return 97;
    if (mkfifo("/fixture-control/response", 0600) != 0 && errno != EEXIST) return 98;
    int request = open("/fixture-control/request", O_RDWR | O_CLOEXEC);
    int response = open("/fixture-control/response", O_RDWR | O_CLOEXEC);
    if (request < 0 || response < 0) return 99;
    FILE *stream = fdopen(request, "r");
    if (!stream) return 100;
    char line[128];
    while (fgets(line, sizeof(line), stream)) {
        int result = 101, target = -1;
        char extra;
        if (strcmp(line, "DEVICE char\n") == 0) result = device_probe("/dev/shm/sandbox-policy-device-char");
        else if (strcmp(line, "DEVICE block\n") == 0) result = device_probe("/dev/shm/sandbox-policy-device-block");
        else if (strcmp(line, "CHAIN\n") == 0) result = execute("/probe/role", 1);
        else if (sscanf(line, "RUN %d %c", &target, &extra) == 1 && target >= 0 && target <= 12) {
            char path[64];
            snprintf(path, sizeof(path), "/probe/target-%d", target);
            result = execute(path, 0);
        } else if (strcmp(line, "PING\n") == 0) result = 0;
        if (dprintf(response, "RESULT %d\n", result) < 0) break;
    }
    fclose(stream);
    close(response);
    return 0;
}
