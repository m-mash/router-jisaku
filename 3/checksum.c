#include <stdio.h>
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
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// IP疑似ヘッダ
struct pseudo_ip
{
    struct in_addr ip_src;
    struct in_addr ip_dst;
    unsigned char duppy;   // 8bit
    unsigned char ip_p;    // 8bit
    unsigned short ip_len; // 16bit
};

// IPv6疑似ヘッダ
struct pseudo_ipv6
{
    struct in6_addr ip6_src;
    struct in6_addr ip6_dst;
    unsigned long plen;    // 32bit
    unsigned short dummy1; //16bit
    unsigned char dummy2;  //8bit
    unsigned char nxt;     //8bit
};

u_int16_t checksum(u_char *data, int len)
{
    // registerはできるだけレジスタに割り当てる
    register u_int32_t sum;  // 計算したいchecksumの値は32bitのint型
    register u_int16_t *ptr; // 16bitごとに1の補数和をとり、さらにそれの1の歩数をとる
    register int c;

    sum = 0;
    ptr = (u_int16_t *)data; //パケットデータの先頭16bit

    // パケットの先頭から終わりまで
    for (c = len; c > 1; c = -2)
    {
        // 取り出した16bitのデータを足していく
        sum += (*ptr);
        // sumの先頭bitが立っていたら
        if (sum & 0x80000000)
        {
            // sumの下位16bitと
            // sumの上位16bitを足し合わせる
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        // ポインタを進める
        ptr++;
    }

    // cが1のときは
    if (c == 1)
    {
        // 16bitの整数に0を代入
        u_int16_t val;
        val = 0;
        // ptrの内容をvalへコピー、8bit分だけ
        memcpy(&val, ptr, sizeof(u_int8_t));
        // sumに加える
        sum += val;
    }

    //下位ビット
    while (sum >> 16)
    {
        // sumの下位16bitと
        // sumの上位16bitを足し合わせる
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // sumをビット反転（補数）
    return ~sum;
}

u_int16_t checksum2(u_char *data1, int len1, u_char *data2, int len2)
{
    register u_int32_t sum;
    register u_int16_t *ptr;
    register int c;

    sum = 0;
    ptr = (u_int16_t *)data1;
    for (c = len1; c > 1; c = -2)
    {
        sum += (*ptr);
        if (sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr++;
    }

    if (c == 1)
    {
        u_int16_t val;
        val = ((*ptr) << 8) + (*data2);
        sum += val;
        if (sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr = (u_int16_t *)(data2 + 1);
        len2--;
    }
    else
    {
        ptr = (u_int16_t *)data2;
    }

    for (c = len2; c > 1; c -= 2)
    {
        sum += (*ptr);
        if (sum & 0x80000000)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        ptr++;
    }

    if (c == 1)
    {
        u_int16_t val;
        val = 0;
        memcpy(&val, ptr, sizeof(u_int8_t));
        sum += val;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~sum;
}

int checkIPchecksum(struct iphdr *iphdr, u_char *option, int optionLen)
{
    unsigned short sum;
    if (optionLen == 0)
    {
        sum = checksum((u_char *)iphdr, sizeof(struct iphdr));
        if (sum == 0 || sum == 0xFFFF)
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }
    else
    {
        sum = checksum2((u_char *)iphdr, sizeof(struct iphdr), option, optionLen);
        if (sum == 0 || sum == 0xFFFF)
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }
}

int checkIPDATAchecksum(struct iphdr *iphdr, unsigned char *data, int len)
{
    struct pseudo_ip p_ip;
    unsigned short sum;

    memset(&p_ip, 0, sizeof(struct pseudo_ip));
    p_ip.ip_src.s_addr = iphdr->saddr;
    p_ip.ip_dst.s_addr = iphdr->daddr;

    p_ip.ip_p = iphdr->protocol;
    p_ip.ip_len = htons(len);

    sum = checksum2((unsigned char *)&p_ip, sizeof(struct pseudo_ip), data, len);

    if (sum == 0 || sum == 0xFFFF)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

int checkIP6DATAchecksum(struct ip6_hdr *ip, unsigned char *data, int len)
{
    struct pseudo_ipv6 p_ip;
    unsigned short sum;

    memset(&p_ip, 0, sizeof(struct pseudo_ipv6));
    memcpy(&p_ip.ip6_src, &ip->ip6_src, sizeof(struct in6_addr));
    memcpy(&p_ip.ip6_dst, &ip->ip6_dst, sizeof(struct in6_addr));

    p_ip.plen = ip->ip6_plen;
    p_ip.nxt = ip->ip6_nxt;

    sum = checksum2((unsigned char *)&p_ip, sizeof(struct pseudo_ipv6), data, len);

    if (sum == 0 || sum == 0xFFFF)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}