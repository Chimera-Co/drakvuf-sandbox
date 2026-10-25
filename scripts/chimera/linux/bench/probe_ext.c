/*
 * CHIMERA Linux extended probe: benign behaviours that probe.c does not cover, chosen from what
 * Linux malware commonly does, to find which of them the Linux telemetry sees (gaps table in
 * docs/chimera/linux-sandbox.md). Runs as root in the disposable guest; touches nothing outside it.
 *
 *   gcc -O2 -o probe-ext probe_ext.c
 *
 * Behaviours:
 *   ptrace     child PTRACE_TRACEME + SIGSTOP, parent PTRACE_CONT          (ptracemon)
 *   ebpf       bpf(BPF_PROG_LOAD) of a 2-instruction socket filter          (ebpfmon)
 *   unix       listen on /tmp/chimera-probe.sock, connect + send to it     (unixsocketmon)
 *   fileless   memfd_create + write /bin/true + execve(/proc/self/fd/N)   (procmon exec)
 *   persist    write /etc/cron.d/chimera-probe and a systemd unit file, then delete both
 *   rename     prctl(PR_SET_NAME, "kworker/0:9")                           (process name)
 *   recon      read /proc/self/status, /sys/class/dmi/id/product_name, /proc/cpuinfo
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/bpf.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static void do_ptrace(void)
{
    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        _exit(0);
    }
    int status;
    waitpid(child, &status, 0);
    ptrace(PTRACE_CONT, child, NULL, NULL);
    waitpid(child, &status, 0);
}

static void do_ebpf(void)
{
    struct bpf_insn prog[] = {
        {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0},
        {.code = BPF_JMP | BPF_EXIT},
    };
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insns = (unsigned long)prog;
    attr.insn_cnt = 2;
    attr.license = (unsigned long)"GPL";
    int fd = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd >= 0)
        close(fd);
}

static void do_unix(void)
{
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    strcpy(a.sun_path, "/tmp/chimera-probe.sock");
    unlink(a.sun_path);
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    int cli = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv >= 0 && cli >= 0 && bind(srv, (struct sockaddr *)&a, sizeof(a)) == 0 && listen(srv, 1) == 0
        && connect(cli, (struct sockaddr *)&a, sizeof(a)) == 0) {
        int peer = accept(srv, NULL, NULL);
        char buf[32];
        send(cli, "chimera-unix-named", 18, 0);
        if (peer >= 0) {
            recv(peer, buf, sizeof(buf), 0);
            close(peer);
        }
    }
    if (cli >= 0)
        close(cli);
    if (srv >= 0)
        close(srv);
    unlink(a.sun_path);
}

static void do_fileless(void)
{
    int src = open("/bin/true", O_RDONLY);
    int mfd = memfd_create("chimera-probe", 0);
    if (src < 0 || mfd < 0)
        return;
    char buf[65536];
    ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0)
        write(mfd, buf, n);
    close(src);
    pid_t child = fork();
    if (child == 0) {
        char path[64];
        snprintf(path, sizeof(path), "/proc/self/fd/%d", mfd);
        char *argv[] = {"chimera-memfd", NULL};
        char *envp[] = {NULL};
        execve(path, argv, envp);
        _exit(127);
    }
    waitpid(child, NULL, 0);
    close(mfd);
}

static void write_file(const char *path, const char *text)
{
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        write(fd, text, strlen(text));
        close(fd);
    }
}

static void do_persist(void)
{
    write_file("/etc/cron.d/chimera-probe", "# chimera probe, removed at once\n");
    write_file("/etc/systemd/system/chimera-probe.service", "[Unit]\nDescription=chimera probe\n");
    unlink("/etc/cron.d/chimera-probe");
    unlink("/etc/systemd/system/chimera-probe.service");
}

static void do_recon(void)
{
    const char *paths[] = {"/proc/self/status", "/sys/class/dmi/id/product_name", "/proc/cpuinfo"};
    char buf[4096];
    for (unsigned i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        int fd = open(paths[i], O_RDONLY);
        if (fd >= 0) {
            read(fd, buf, sizeof(buf));
            close(fd);
        }
    }
}

int main(void)
{
    do_recon();
    do_ptrace();
    do_ebpf();
    do_unix();
    do_fileless();
    do_persist();
    prctl(PR_SET_NAME, "kworker/0:9");
    usleep(200000);
    printf("probe-ext done\n");
    return 0;
}
