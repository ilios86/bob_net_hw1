#include "pcap.h"
//#include "header.h"
#include <libnet.h>
#include <arpa/inet.h>

using namespace std;

unsigned long pkt_cnt = 0;
/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main()
{
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];


    char *dev;    // 사용중인 네트웍 디바이스 이름
    dev = pcap_lookupdev(errbuf);
    // 에러가 발생했을경우
    if(dev == NULL)
    {
        printf("%s\n",errbuf);
        return -1;
    }
    // 네트웍 디바이스 이름 출력
    printf("DEV: %s\n",dev);

    /* Open the device */
    if ( (adhandle= pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf) ) == NULL)
    {
        fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", dev);
        return -1;
    }
    /* start the capture */
    pcap_loop(adhandle, 0, packet_handler, NULL);

    return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{

//    FILE *fd = fopen("packet.log", "a");
    FILE *fd = stdout;


//    int ethernet_header_len, ip_header_len, tcp_header_len;
//    ethernet_header_len = 14;
    struct libnet_ethernet_hdr* eth_h = (struct libnet_ethernet_hdr*)pkt_data;

    pkt_cnt++;
    unsigned short ip_type = ntohs(eth_h->ether_type);
    if (ip_type != 0x800) {
        return;
    }
    struct libnet_ipv4_hdr *ip_h = (struct libnet_ipv4_hdr*)&pkt_data[LIBNET_ETH_H];
    if (ip_h->ip_p != 0x6) // TCP protocol
        return;

    fprintf(fd, "============== packet %5lu (id:0x%04x) information ===============\n", pkt_cnt, ntohs(ip_h->ip_id));
    // print mac address
    //ip_header_len = (ip_h->ip_hl)*4;
    struct libnet_tcp_hdr *tcp_h = (struct libnet_tcp_hdr*)&pkt_data[LIBNET_ETH_H+LIBNET_IPV4_H];

    fprintf(fd, "MAC :: SRC[%02X:%02X:%02X:%02X:%02X:%02X] --> ",pkt_data[6], pkt_data[7], pkt_data[8], pkt_data[9], pkt_data[10], pkt_data[11]);
    fprintf(fd, "[%02X:%02X:%02X:%02X:%02X:%02X]DEST \n",pkt_data[0], pkt_data[1], pkt_data[2], pkt_data[3], pkt_data[4], pkt_data[5]);

    char ip_src[INET_ADDRSTRLEN],ip_dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_h->ip_src.s_addr, ip_src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip_h->ip_dst.s_addr, ip_dst, INET_ADDRSTRLEN);
    fprintf(fd, "IP :: SRC[%s] --> [%s]DEST\n", ip_src, ip_dst);
    fprintf(fd, "port :: SRC[%u] --> [%u]DEST\n", ntohs(tcp_h->th_sport), ntohs(tcp_h->th_dport));

    const u_char *payload = (pkt_data + LIBNET_ETH_H + LIBNET_IPV4_H + LIBNET_TCP_H);

    int payload_len = ip_h->ip_len - LIBNET_IPV4_H - LIBNET_TCP_H;
    //fprintf(fd, "DATA(%d)>>\n", payload_len);
    //fprint_hex(fd, payload, payload_len);

    fprintf(fd, "====================================================================\n\n");
}


void fprint_hex(FILE *fd, const u_char *addr, int len) {
    int i;
    unsigned char buff[17];
    const u_char *pc = addr;

    if (len == 0) {
        fprintf(fd, "  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        fprintf(fd, "  NEGATIVE LENGTH: %i\n",len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                fprintf (fd, "  %s\n", buff);

            // Output the offset.
            fprintf (fd, "  %04x ", i);
        }

        // Now the hex code for the specific character.
        fprintf (fd, " %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        fprintf (fd, "   ");
        i++;
    }

    // And print the final ASCII bit.
    fprintf (fd, "  %s\n", buff);
}
