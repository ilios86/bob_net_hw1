#ifndef HEADER_H
#define HEADER_H

// 4 bytes IP address
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

// 20 bytes IP Header
typedef struct ip_header{
    u_char ver_ihl; // Version (4 bits) + Internet header length (4 bits)
    u_char tos; // Type of service
    u_short tlen; // Total length
    u_short identification; // Identification
    u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
    u_char ttl; // Time to live
    u_char proto; // Protocol
    u_short crc; // Header checksum
    ip_address saddr; // Source address
    ip_address daddr; // Destination address
    // u_int op_pad; // Option + Padding -- NOT NEEDED!
}ip_header;

//"Simple" struct for TCP
typedef struct tcp_header {
    u_short sport; // Source port
    u_short dport; // Destination port
    u_int seqnum; // Sequence Number
    u_int acknum; // Acknowledgement number
    u_char th_off; // Header length
    u_char flags; // packet flags
    u_short win; // Window size
    u_short crc; // Header Checksum
    u_short urgptr; // Urgent pointer...still don't know what this is...
}tcp_header;


#endif // HEADER_H
