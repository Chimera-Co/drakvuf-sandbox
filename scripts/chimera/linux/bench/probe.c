/*
 * CHIMERA Linux probe: a benign ELF with known behaviour, used to check that each kind of
 * Linux telemetry is captured (docs/chimera/linux-sandbox.md, reliability runs).
 * Every action is local or goes to the contained guest network (answered by INetSim).
 *
 *   gcc -O2 -o probe-dyn probe.c && gcc -O2 -static -o probe-static probe.c
 *
 * Expected events (the checker looks for these):
 *   exec   /bin/sh -c "id; uname -a" and its children (fork/exec/wait)
 *   files  create+write /tmp/chimera-probe.txt, rename to .moved, chmod 0700, symlink, unlink
 *   net    TCP connect to 203.0.113.10:80 + HTTP GET; UDP DNS query for probe.chimera.test;
 *          AF_UNIX socketpair message
 *   proc   a thread (clone with CLONE_THREAD), a child that exits with status 3
 */
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void *thread_main(void *arg)
{
    (void)arg;
    usleep(100000);
    return NULL;
}

static void files(void)
{
    int fd = open("/tmp/chimera-probe.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        const char msg[] = "chimera probe\n";
        write(fd, msg, sizeof(msg) - 1);
        close(fd);
    }
    rename("/tmp/chimera-probe.txt", "/tmp/chimera-probe.moved");
    chmod("/tmp/chimera-probe.moved", 0700);
    symlink("/tmp/chimera-probe.moved", "/tmp/chimera-probe.link");
    unlink("/tmp/chimera-probe.link");
    unlink("/tmp/chimera-probe.moved");
}

static void tcp(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(80)};
    inet_pton(AF_INET, "203.0.113.10", &a.sin_addr);
    if (s >= 0 && connect(s, (struct sockaddr *)&a, sizeof(a)) == 0) {
        const char req[] = "GET /chimera-probe HTTP/1.0\r\nHost: probe.chimera.test\r\n\r\n";
        char buf[512];
        send(s, req, sizeof(req) - 1, 0);
        recv(s, buf, sizeof(buf), 0);
    }
    if (s >= 0)
        close(s);
}

static void dns(void)
{
    /* Hand-made DNS query (A probe.chimera.test) sent with sendto, no resolver library */
    static const unsigned char q[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        5, 'p', 'r', 'o', 'b', 'e', 7, 'c', 'h', 'i', 'm', 'e', 'r', 'a', 4, 't', 'e', 's', 't', 0,
        0x00, 0x01, 0x00, 0x01};
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(53)};
    inet_pton(AF_INET, "198.51.100.53", &a.sin_addr);
    if (s >= 0) {
        char buf[512];
        struct timeval tv = {.tv_sec = 2};
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        sendto(s, q, sizeof(q), 0, (struct sockaddr *)&a, sizeof(a));
        recv(s, buf, sizeof(buf), 0);
        close(s);
    }
}

static void unix_socket(void)
{
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
        char buf[32];
        send(sv[0], "chimera-unix", 12, 0);
        recv(sv[1], buf, sizeof(buf), 0);
        close(sv[0]);
        close(sv[1]);
    }
}

int main(void)
{
    pthread_t t;
    int status;

    pthread_create(&t, NULL, thread_main, NULL);
    files();
    tcp();
    dns();
    unix_socket();
    system("id; uname -a");
    pid_t child = fork();
    if (child == 0)
        _exit(3);
    waitpid(child, &status, 0);
    pthread_join(t, NULL);
    printf("probe done\n");
    return 0;
}
