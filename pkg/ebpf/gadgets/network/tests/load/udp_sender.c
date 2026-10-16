#define _GNU_SOURCE
#include <arpa/inet.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static double now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: sender SECONDS RATE CPU\n");
        return 1;
    }
    int seconds = atoi(argv[1]), rate = atoi(argv[2]), cpu = atoi(argv[3]);
    if (seconds <= 0 || rate <= 0 || cpu < 0 || cpu >= CPU_SETSIZE)
        return 1;
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(cpu, &cpus);
    if (sched_setaffinity(0, sizeof(cpus), &cpus)) {
        perror("sched_setaffinity");
        return 1;
    }

    int send4 = socket(AF_INET, SOCK_DGRAM, 0);
    int send6 = socket(AF_INET6, SOCK_DGRAM, 0);
    int recv4 = socket(AF_INET, SOCK_DGRAM, 0);
    int recv6 = socket(AF_INET6, SOCK_DGRAM, 0);
    if (send4 < 0 || send6 < 0 || recv4 < 0 || recv6 < 0) {
        perror("socket");
        return 1;
    }
    int one = 1;
    if (setsockopt(recv6, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one))) {
        perror("setsockopt");
        return 1;
    }
    struct sockaddr_in dst4 = {.sin_family = AF_INET, .sin_port = htons(999)};
    struct sockaddr_in6 dst6 = {.sin6_family = AF_INET6, .sin6_port = htons(999)};
    inet_pton(AF_INET, "127.0.0.1", &dst4.sin_addr);
    inet_pton(AF_INET6, "::1", &dst6.sin6_addr);
    if (bind(recv4, (void *)&dst4, sizeof(dst4)) ||
        bind(recv6, (void *)&dst6, sizeof(dst6))) {
        perror("bind");
        return 1;
    }
    if (connect(send4, (void *)&dst4, sizeof(dst4)) ||
        connect(send6, (void *)&dst6, sizeof(dst6))) {
        perror("connect");
        return 1;
    }

    double start = now(), end = start + seconds;
    unsigned long sent = 0, errors = 0;
    while (now() < end) {
        for (int i = 0; i < 100; i++) {
            if (send(sent % 2 ? send6 : send4, "naut1587", 8, 0) == 8)
                sent++;
            else
                errors++;
        }
        double target = start + (double)sent / rate;
        double delay = target - now();
        if (delay > 0) {
            struct timespec pause = {
                .tv_sec = (time_t)delay,
                .tv_nsec = (long)((delay - (time_t)delay) * 1e9),
            };
            nanosleep(&pause, NULL);
        }
    }
    printf("{\"sent\":%lu,\"errors\":%lu,\"seconds\":%.3f}\n",
           sent, errors, now() - start);
    return errors != 0;
}
