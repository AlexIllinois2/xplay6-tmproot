/* acceptprobe2 — "gdbserver 的 accept 到底死在哪一步" 的分步探针（v2・修 acceptprobe 的时序 bug）
 *
 * v1 的问题（现读）：child 一 fork 出来就 accept（fd 已被设成非阻塞），
 *   而测试者是从**父进程 sleep(6) 的窗口里**才连进来 ⇒ v1 永远打印 `accept = -1 errno=11(EAGAIN)`
 *   ＝**测不到东西**（2026-10-28 现读复现：`socket/bind/listen` 全 errno=0・`child accept = -1 errno=11`）。
 * v2 改三件事：
 *   ①child 先 sleep(WAIT) 让对端连进来、再**循环** accept 若干秒・每次把 errno 逐次打出来（分得清 EAGAIN / EBADF / 成功）；
 *   ②测完第一轮之后**关掉再重开一次 listen**（第二周期）・因为 README 断言"这台 ROM 只有首个 listen 周期能 accept"＝
 *     这条要能被本探针**独立复现**，否则"EBADF"这句话就还是只信 README；
 *   ③把自己是谁打出来（uid・SELinux context・pid），因为"谁起的"就是要害（su -c 的 init 域 vs root 守护通道）。
 *
 * 用法＝`acceptprobe2 <port> [wait_s] [loops]`（默认 5044・wait 4 s・loops 12）
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void nb(int fd) { int fl = fcntl(fd, F_GETFL); fcntl(fd, F_SETFL, fl | O_NONBLOCK); }

static int up(int port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { printf("socket = -1 errno=%d\n", errno); return -1; }
    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = INADDR_ANY;
    if (bind(s, (struct sockaddr *)&a, sizeof a)) { printf("bind = -1 errno=%d\n", errno); return -1; }
    if (listen(s, 4)) { printf("listen = -1 errno=%d\n", errno); return -1; }
    printf("  socket+bind+listen ok fd=%d\n", s);
    return s;
}

/* 一轮：fork 一个 child・sleep(wait) 让对端连进来・然后循环 accept */
static int round(const char *tag, int port, int wait_s, int loops)
{
    int s = up(port);
    if (s < 0) return -1;
    nb(s);
    pid_t p = fork();
    if (p == 0) {
        sleep(wait_s);
        int got = -1;
        for (int i = 0; i < loops; i++) {
            int c = accept(s, NULL, NULL);
            printf("  %s accept#%d = %d errno=%d%s\n", tag, i, c, c < 0 ? errno : 0,
                   c < 0 ? (errno == EAGAIN ? " (EAGAIN=还没人来连)" : errno == EBADF ? " (EBADF=这台 ROM 的那一刀)" : "") : " (★连上了)");
            fflush(stdout);
            if (c >= 0) { got = c; break; }
            sleep(1);
        }
        if (got >= 0) close(got);
        _exit(got >= 0 ? 0 : 1);
    }
    int st;
    waitpid(p, &st, 0);
    close(s);
    return WEXITSTATUS(st);
}

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 5044;
    int wait_s = argc > 2 ? atoi(argv[2]) : 4;
    int loops = argc > 3 ? atoi(argv[3]) : 12;
    char buf[512];
    FILE *f;
    printf("acceptprobe2 port=%d wait=%ds loops=%d uid=%d pid=%d\n", port, wait_s, loops, (int)getuid(), (int)getpid());
    if ((f = fopen("/proc/self/attr/current", "r"))) {
        if (fgets(buf, sizeof buf, f)) printf("  selinux context＝%s", buf);
        fclose(f);
    }
    struct stat sb;
    if (!stat("/dev/binder", &sb)) printf("  （/dev/binder 存在＝binder 可用）・打开的 fd 数见下\n");

    printf("第 1 轮（首次 listen 周期）・%ds 内从主机连 127.0.0.1:<forward 端口>\n", wait_s);
    int r1 = round("R1", port, wait_s, loops);
    printf("第 1 轮结果＝%s\n", r1 == 0 ? "accept 成功" : "accept 失败");

    printf("第 2 轮（**关掉再重开 listen**・README 断言这一轮必 EBADF）\n");
    int r2 = round("R2", port, wait_s, loops);
    printf("第 2 轮结果＝%s\n", r2 == 0 ? "accept 成功＝README 那条断言**不成立**" : "accept 失败＝与 README 一致");
    fflush(stdout);
    return 0;
}
