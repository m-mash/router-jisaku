#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include "netutil.h"

typedef struct
{
    char *Device1;
    char *Device2;
    int DebugOut;
} PARAM;

PARAM Param = {"ens38", "ens39", 0};

typedef struct
{
    int soc;
} DEVICE;

DEVICE Device[2];

int EndFlag = 0;

int DebugPrintf(char *fmt, ...)
{
    if (Param.DebugOut)
    {
        va_list args;
        va_start(args, fmt);
        vfprintf(stderr, fmt, args);
        va_end(args);
    }

    return 0;
}

int DebugPerror(char *msg)
{
    if (Param.DebugOut)
    {
        fprintf(stderr, "%s : %s\n", msg, strerror(errno));
    }
    return 0;
}

int AnalyzePacket(int deviceNo, u_char *data, int size)
{
    u_char *ptr;
    int lest;
    struct ether_header *eh;

    // Ethernetフレームの先頭のポインタ
    ptr = data;
    // Ethernetフレーム全体のサイズ
    lest = size;
    // EthernetフレームのサイズがEthernetヘッダより小さかったら
    if (lest < sizeof(struct ether_header))
    {
        DebugPrintf("[%d]:lest(%d) < sizeof(struct ether_header)\n", deviceNo, lest);
        return -1;
    }

    // ポインタの型を変換
    eh = (struct ether_header *)ptr;
    // ポインタをヘッダ分進める
    ptr += sizeof(struct ether_header);
    // サイズをヘッダ分減らす
    lest -= sizeof(struct ether_header);
    DebugPrintf("[%d]", deviceNo);
    if (Param.DebugOut)
    {
        PrintEtherHeader(eh, stderr);
    }
    return 0;
}

int Bridge()
{
    // pollfdの配列で管理されたファイルディスクリプタたちの
    // 状態変化を監視する
    struct pollfd targets[2];
    int nready, i, size;
    u_char buf[2048];

    targets[0].fd = Device[0].soc;
    targets[0].events = POLLIN | POLLERR;
    targets[1].fd = Device[1].soc;
    targets[1].events = POLLIN | POLLERR;

    while (EndFlag == 0)
    {
        switch (nready = poll(targets, 2, 100))
        {
        // エラー
        case -1:
            if (errno != EINTR)
            {
                perror("poll");
            }
            break;
        // タイムアウト：どのファイルディスクリプタでも
        // イベントが発生しなかった
        case 0:
            break;
        // revents要素をもつfds構造体が2つあった
        default:
            for (i = 0; i < 2; i++)
            {
                if (targets[i].revents & (POLLIN | POLLERR))
                {
                    // パケットを受信できなかったら
                    if ((size = read(Device[i].soc, buf, sizeof(buf))) <= 0)
                    {
                        perror("read");
                    }
                    // パケットを受信できたら
                    else
                    {
                        // パケットを解析して
                        // 正常に解析が終了すれば
                        if (AnalyzePacket(i, buf, size) != -1)
                        {
                            // 受信したインタフェースでないほうに
                            // writeする
                            if (size = write(Device[(!i)].soc, buf, size) <= 0)
                                perror("write");
                        }
                    }
                }
            }
            break;
        }
    }
}

// "/proc/sys/net/ipv4/ip_forward"に0を書き込んで、
// IPフォワードをしない設定に
int DisableIpForward()
{
    FILE *fp;
    // ファイルがOpenできなかったら
    // return -1
    if ((fp = fopen("/proc/sys/net/ipv4/ip_forward", "w")) == NULL)
    {
        DebugPrintf("cannot write /proc/sys/net/ipv4/ip_forward\n");
        return -1;
    }
    fputs("0", fp);
    fclose(fp);

    return 0;
}

void EndSignal(int sig)
{
    EndFlag = 1;
}

int main(int argc, char *argv[], char *envp[])
{
    // 各デバイス名をInitRawSocketに渡してソケットを初期化して、
    // Device構造体の配列要素にいれる
    if ((Device[0].soc = InitRawSocket(Param.Device1, 1, 0)) == -1)
    {
        DebugPrintf("InitRawSocket:error:%s\n", Param.Device1);
        return -1;
    }
    DebugPrintf("%s OK\n", Param.Device1);
    if ((Device[1].soc = InitRawSocket(Param.Device2, 1, 0)) == -1)
    {
        DebugPrintf("InitRawSocket:error:%s\n", Param.Device2);
        return -1;
    }
    DebugPrintf("%s OK\n", Param.Device2);

    // カーネルのパケット転送を禁止
    DisableIpForward();

    // SIGxxxのシグナルが発生時、
    // EndSignalが呼ばれる
    signal(SIGINT, EndSignal);
    signal(SIGTERM, EndSignal);
    signal(SIGQUIT, EndSignal);
    signal(SIGPIPE, EndSignal);
    signal(SIGTTIN, EndSignal);
    signal(SIGTTOU, EndSignal);

    DebugPrintf("bridge start\n");

    // ブリッジが起動
    Bridge();

    DebugPrintf("bridge end\n");

    // 各デバイスのソケットを閉じる
    close(Device[0].soc);
    close(Device[1].soc);

    return 0;
}
