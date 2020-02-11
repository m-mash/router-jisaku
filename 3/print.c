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

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6 0x86dd
#endif

char *my_ether_ntoa_r(u_char *hwaddr, char *buf, socklen_t size)
{
    snprintf(buf, size, "%02x:%02x:%02x:%02x:%02x:%02x:", hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);
    return buf;
}

char *arp_ip2str(u_int8_t *ip, char *buf, socklen_t size)
{
    snprintf(buf, size, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return buf;
}

char *ip_ip2str(u_int32_t ip, char *buf, socklen_t size)
{
    struct in_addr *addr;
    addr = (struct in_addr *)&ip;
    inet_ntop(AF_INET, addr, buf, size);
    return buf;
}

int PrintEtherHeader(struct ether_header *eh, FILE *fp)
{
    char buf[80];

    fprintf(fp, "\n\nETHER:\n  ether_src = %s, ether_dst = %s, type = %02X", my_ether_ntoa_r(eh->ether_shost, buf, sizeof(buf)), my_ether_ntoa_r(eh->ether_dhost, buf, sizeof(buf)), ntohs(eh->ether_type));

    switch (eh->ether_type)
    {
    case ETH_P_IP:
        fprintf(fp, "(IP)");
        break;
    case ETH_P_IPV6:
        fprintf(fp, "(IPV6)");
        break;
    case ETH_P_ARP:
        fprintf(fp, "(ARP)");
        break;
    default:
        fprintf(fp, "(unknown)");
        break;
    }

    return 1;
}

int PrintArp(struct ether_arp *arp, FILE *fp)
{
    static char *hrd[] = {
        "From KA9Q: NET/ROM psudo",
        "Ethernet 10/100Mbps",
        "Experimental Ethernet",
        "AX.25 level 2",
        "PROnet token ring",
        "Chaosnet",
        "IEEE 802.2 Ethernet/TR/TB",
        "ARCnet",
        "APPLEtalk",
        "undefine",
        "undefine",
        "undefine",
        "undefine",
        "undefine",
        "undefine",
        "Frame Relay DLCI",
        "undefine",
        "undefine",
        "undefine",
        "ATM",
        "undefine",
        "undefine",
        "undefine",
        "Metricom STRIP(new IANA id)"};

    static char *op[] = {
        "undefined",
        "ARP Request",
        "ARP Reply",
        "RARP Request",
        "RARP Reply",
        "undefined",
        "undefined",
        "undefined",
        "InARP Request",
        "InRARP Reply",
        "(ATM) APP NAK"};

    char buf[80];

    fprintf(fp, "\nARP:\n");
    fprintf(fp, "  arp_hrd = %u", ntohs(arp->arp_hrd));
    if (ntohs(arp->arp_hrd < +23))
    {
        fprintf(fp, "(%s)", hrd[ntohs(arp->arp_hrd)]);
    }
    else
    {
        fprintf(fp, "(undefined)");
    }

    fprintf(fp, ", arp_pro=%u", ntohs(arp->arp_pro));
    switch (ntohs(arp->arp_pro))
    {
    case ETHERTYPE_IP:
        fprintf(fp, "(IP)\n");
        break;
    case ETHERTYPE_ARP:
        fprintf(fp, "(ARP)\n");
        break;
    case ETHERTYPE_REVARP:
        fprintf(fp, "(RARP)\n");
        break;
    case ETHERTYPE_IPV6:
        fprintf(fp, "(IPv6)\n");
        break;
    default:
        fprintf(fp, "(unknown)\n");
        break;
    }
    fprintf(fp, "  arp_hln = %u, arp_pln = %u, arp_op = %u", arp->arp_hln, arp->arp_pln, arp->arp_op);
    if (ntohs(arp->arp_op) <= 10)
    {
        fprintf(fp, ", (%s)\n", op[ntohs(arp->arp_op)]);
    }
    else
    {
        fprintf(fp, "(undefine)");
    }
    fprintf(fp, "  arp_sha = %s", my_ether_ntoa_r(arp->arp_sha, buf, sizeof(buf)));
    fprintf(fp, ", arp_spa = %s", arp_ip2str(arp->arp_spa, buf, sizeof(buf)));
    fprintf(fp, ", arp_tha = %s", my_ether_ntoa_r(arp->arp_sha, buf, sizeof(buf)));
    fprintf(fp, ", arp_tpa = %s", arp_ip2str(arp->arp_tpa, buf, sizeof(buf)));

    return -1;
}

static char *Proto[] = {
    "undefined",
    "ICMP",
    "IGMP",
    "undefined",
    "IPIP",
    "undefined",
    "TCP",
    "undefined",
    "EGP",
    "undefined",
    "undefined",
    "undefined",
    "PUP"
    "undefined",
    "undefined",
    "undefined",
    "undefined",
    "UDP"};

int PrintIpHeader(struct iphdr *iphdr, u_char *option, int optionLen, FILE *fp)
{
    // int i;
    // char buf[80];
    fprintf(fp, "\nIP:\n");
    fprintf(fp, "  version = %u", iphdr->version);
    fprintf(fp, ", ihl = %u", iphdr->ihl);
    fprintf(fp, ", tos = %x", iphdr->tos);
    fprintf(fp, ", tot_len = %u", ntohs(iphdr->tot_len));
    fprintf(fp, ", id = %u", ntohs(iphdr->id));
    fprintf(fp, ", flag_off = %x, %u", (ntohs(iphdr->frag_off) >> 13) & 0x07, ntohs(iphdr->frag_off) & 0x1FFF);
    fprintf(fp, ", ttl = %u", iphdr->ttl);
    fprintf(fp, ", protocol = %u", iphdr->protocol);
    if (iphdr->protocol <= 17)
    {
        fprintf(fp, ", (%s)", Proto[iphdr->protocol]);
    }
    else
    {
        fprintf(fp, ", (undefined)");
    }

    // more print contents here...

    return 0;
}

int PrintIp6Header(struct ip6_hdr *ip6_hdr, FILE *fp)
{
    char buf[80];
    fprintf(fp, "\nIPv6:\n");
    fprintf(fp, "ip6_flow = %x", ip6_hdr->ip6_flow);
    fprintf(fp, ", ip6_plen = %d", ip6_hdr->ip6_plen);
    fprintf(fp, ", ip6_flow = %u", ip6_hdr->ip6_nxt);
    if (ip6_hdr->ip6_nxt <= 17)
    {
        fprintf(fp, "(%s)", Proto[ip6_hdr->ip6_nxt]);
    }
    else
    {
        fprintf(fp, ", (undefined)");
    }

    fprintf(fp, ", ip6_hlim = %d", ip6_hdr->ip6_hlim);
    fprintf(fp, ", ip6_src = %s", inet_ntop(AF_INET6, &ip6_hdr->ip6_src, buf, sizeof(buf)));
    fprintf(fp, ", ip6_dst = %s", inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, buf, sizeof(buf)));

    return 0;
}

int PrintIcmp(struct icmp *icmp, FILE *fp)
{
    static char *icmp_type[] = {
        "Echo Reply",
        "undefined",
        "undefined",
        "Destination Unreachable",
        "source Quench",
        "Redirect",
        "undefined",
        "undefined",
        "Echo Request",
        "Router Advertisement",
        "Router Seletion",
        "Time Exceeded for Datagram",
        "Parameter Problem on Datagram",
        "Timestamp Request",
        "Timestamp Reply",
        "Information Request",
        "Information Reply",
        "Address Mask Request",
        "Address Mask Reply"};

    fprintf(fp, "\nICMP:\n");
    fprintf(fp, "icmp_type = %u", icmp->icmp_type);
    if (icmp->icmp_type <= 18)
    {
        fprintf(fp, "(%s)", icmp_type[icmp->icmp_type]);
    }
    else
    {
        fprintf(fp, "(undefined)");
    }

    fprintf(fp, ", icmp_code = %u", icmp->icmp_code);
    fprintf(fp, ", icmp_cksum = %u", ntohs(icmp->icmp_cksum));

    if (icmp->icmp_type == 0 || icmp->icmp_type == 8)
    {
        fprintf(fp, ", icmp_id = %u", ntohs(icmp->icmp_id));
        fprintf(fp, ", icmp_seq = %u\n", ntohs(icmp->icmp_seq));
    }

    return 0;
}

int PrintIcmp6(struct icmp6_hdr *icmp6, FILE *fp)
{
    fprintf(fp, "\nICMPV6:\n");
    fprintf(fp, "icmp_type = %u ", icmp6->icmp6_type);
    if (icmp6->icmp6_type == 1)
    {
        fprintf(fp, "(Destination Unreachable)");
    }
    else if (icmp6->icmp6_type == 2)
    {
        fprintf(fp, "(Packet Too Big)");
    }
    else if (icmp6->icmp6_type == 3)
    {
        fprintf(fp, "(Time Exceeded)");
    }
    else if (icmp6->icmp6_type == 4)
    {
        fprintf(fp, "(Parameter Problem)");
    }
    else if (icmp6->icmp6_type == 128)
    {
        fprintf(fp, "(Echo Request)");
    }
    else if (icmp6->icmp6_type == 129)
    {
        fprintf(fp, "(Echo Reply)");
    }
    else
    {
        fprintf(fp, "(undefined)");
    }

    fprintf(fp, ", icmp6_code = %u", icmp6->icmp6_code);
    fprintf(fp, ", icmp6_cksum = %u", ntohs(icmp6->icmp6_cksum));

    if (icmp6->icmp6_type == 128 || icmp6->icmp6_type == 129)
    {
        fprintf(fp, ", icmp6_id = %u", ntohs(icmp6->icmp6_id));
        fprintf(fp, ", icmp6_seq = %u\n", ntohs(icmp6->icmp6_seq));
    }

    return 0;
}

int PrintTcp(struct tcphdr *tcphdr, FILE *fp)
{
    fprintf(fp, "\nTCP:\n");
    fprintf(fp, "  src = %u", ntohs(tcphdr->source));
    fprintf(fp, ", dst = %u", ntohs(tcphdr->dest));
    fprintf(fp, ", seq = %u", ntohl(tcphdr->seq));
    fprintf(fp, ", ack_seq = %u", ntohl(tcphdr->ack_seq));
    fprintf(fp, "\n  doff = %u", ntohl(tcphdr->doff));
    fprintf(fp, ", urg = %u", ntohl(tcphdr->urg));
    fprintf(fp, ", ack = %u", ntohl(tcphdr->ack));
    fprintf(fp, ", psh = %u", ntohl(tcphdr->psh));
    fprintf(fp, ", rst = %u", ntohl(tcphdr->rst));
    fprintf(fp, ", syn = %u", ntohl(tcphdr->syn));
    fprintf(fp, ", fin = %u", ntohl(tcphdr->fin));
    fprintf(fp, "\n  th_win = %u", ntohs(tcphdr->window));
    fprintf(fp, ", th_sum = %u", ntohs(tcphdr->check));
    fprintf(fp, ", th_urp = %u", ntohs(tcphdr->urg_ptr));

    return 0;
}

int PrintUdp(struct udphdr *udphdr, FILE *fp)
{
    fprintf(fp, "\nUDP:\n");
    fprintf(fp, "src = %u", ntohs(udphdr->source));
    fprintf(fp, ", dst = %u", ntohs(udphdr->dest));
    fprintf(fp, ", len = %u", ntohs(udphdr->len));
    fprintf(fp, ", checksum = %u", ntohs(udphdr->check));

    return 0;
}