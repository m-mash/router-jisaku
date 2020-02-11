#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include "analyze.h"

// ソケットを初期化して取得する関数
// device      : ネットワークインタフェース名を指定
// promiscFlag : 1 on , 0 off (default)
// ipOnly      :
int InitRawSocket(char *device, int promiscFlag, int ipOnly)
{
    struct ifreq ifreq;
    struct sockaddr_ll sa;
    int soc;

    // 設定したオプション
    if (ipOnly)
    {
        // int domain   = PF_PAKCET (データリンク層
        // int type     = SOCK_RAW  (生のネットワークプロトコルへのアクセス
        // int protocol = ETH_P_IP  (IPパケットのみ
        // soc : ソケットのファイルディスクリプタ
        if ((soc = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
        {
            perror("socket");
            return -1;
        }
    }
    else
    {
        if ((soc = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 1)
        {
            perror("socket");
            return -1;
        }
    }

    // ifreqのアドレスからsizeof(struct ifreq)分だけ0埋め
    memset(&ifreq, 0, sizeof(struct ifreq));
    // ifreq.ifr_nameにdevice名を上書き
    strncpy(ifreq.ifr_name, device, sizeof(ifreq.ifr_name) - 1);
    // ioctlで、IF名に対応したインタフェースのインデックスを取得
    // エラーの場合0を返す
    if (ioctl(soc, SIOCGIFINDEX, &ifreq) < 0)
    {
        perror("ioctl");
        close(soc);
        return -1;
    }

    // Ethernetのソケットをつくる
    sa.sll_family = AF_PACKET;
    if (ipOnly)
    {
        sa.sll_protocol = htons(ETH_P_IP);
    }
    else
    {
        sa.sll_protocol = htons(ETH_P_ALL);
    }

    sa.sll_ifindex = ifreq.ifr_ifindex;

    // socketをアドレスファミリーにバインドする
    if (bind(soc, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        perror("bind");
        close(soc);
        return -1;
    }

    // promiscuous modeなら、
    if (promiscFlag)
    {
        // socで指定されるfdからフラグを取得する
        // 取得したフラグはifreqにセットされる？
        if (ioctl(soc, SIOCGIFFLAGS, &ifreq) < 0)
        {
            perror("ioctl");
            close(soc);
            return -1;
        }

        // PROMISCのフラグをたてて更新する
        ifreq.ifr_flags = (ifreq.ifr_flags | IFF_PROMISC);

        // socで指定されるfdにフラグをセットする
        if (ioctl(soc, SIOCSIFFLAGS, &ifreq) < 0)
        {
            perror("ioctl");
            close(soc);
            return -1;
        }
    }

    return soc;
}

int main(int argc, char *argv[], char *envp[])
{
    int soc, size;
    u_char buf[65535];

    if (argc <= 1)
    {
        fprintf(stderr, "ltest device-name\n");
        return 1;
    }

    if ((soc = InitRawSocket(argv[1], 0, 0)) == 1)
    {
        fprintf(stderr, "InitRawSocket:Error:%s\n", argv[1]);
        return -1;
    }

    while (1)
    {
        if ((size = read(soc, buf, sizeof(buf))) <= 0)
        {
            perror("read");
        }
        else
        {
            AnalyzePacket(buf, size);
        }
    }
    close(soc);

    return 0;
}
