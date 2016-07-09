#include "pcap.h"
#include "header.h"
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


    int ethernet_header_len, ip_header_len, tcp_header_len;
    ethernet_header_len = 14;

    pkt_cnt++;
    unsigned short ip_type = ntohs(*(unsigned short*)&pkt_data[12]);
    if (ip_type != 0x800) {
        return;
    }
    ip_header *ip_h = (ip_header*)&pkt_data[14];
    if (ip_h->proto != 0x6) // TCP protocol
        return;

    fprintf(fd, "============== packet %5lu (id:0x%04x) information ===============\n", pkt_cnt, ntohs(ip_h->identification));
    // print mac address
    ip_header_len = (ip_h->ver_ihl & 0x0F)*4;
    tcp_header *tcp_h = (tcp_header*)&pkt_data[14+ip_header_len];

    fprintf(fd, "MAC :: SRC[%02X:%02X:%02X:%02X:%02X:%02X] --> ",pkt_data[6], pkt_data[7], pkt_data[8], pkt_data[9], pkt_data[10], pkt_data[11]);
    fprintf(fd, "[%02X:%02X:%02X:%02X:%02X:%02X]DEST \n",pkt_data[0], pkt_data[1], pkt_data[2], pkt_data[3], pkt_data[4], pkt_data[5]);

    fprintf(fd, "IP :: SRC[%hu.%hu.%hu.%hu] --> [%hu.%hu.%hu.%hu]DEST\n",
            ip_h->saddr.byte1, ip_h->saddr.byte2, ip_h->saddr.byte3, ip_h->saddr.byte4,
            ip_h->daddr.byte1, ip_h->daddr.byte2, ip_h->daddr.byte3, ip_h->daddr.byte4);
    fprintf(fd, "port :: SRC[%u] --> [%u]DEST\n", ntohs(tcp_h->sport), ntohs(tcp_h->dport));

    tcp_header_len = tcp_h->th_off / 4;
    const u_char *payload = (pkt_data + ethernet_header_len + ip_header_len + tcp_header_len);

    int payload_len = ip_h->tlen - ip_header_len - tcp_header_len;
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
