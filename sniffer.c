#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/if_ether.h>  
#include <netinet/ip.h>        
#include <netinet/tcp.h>       
#include <netinet/udp.h>       
#include <netinet/ip6.h>
#include "sniffer.h"
#include <time.h>
#include <sys/time.h>


static pcap_t *handle = NULL;


/**
 * @brief Appends an "or" logical operator to the filter string.
 * @param filter_exp The filter expression string where "or" will be appended.
 * @param first_condition_added A pointer to an int that tracks whether any conditions have already been added to the filter.
 */

void add_or(char *filter_exp, int *first_condition_added) {
    if (*first_condition_added) {
        strcat(filter_exp, " or ");
    } else { 
        *first_condition_added = 1;
    }  
}

/**
 * @brief Constructs and applies a pcap filter based on specified criteria in the Arguments structure.
 * Create a filter string with specified criteria from Arguments structure
 */
void apply_filters(pcap_t *handle, Arguments *args, bpf_u_int32 net) {
    struct bpf_program fp;  
    char filter_exp[1024] = ""; 
    int first_condition_added = 0; 

    if (args->tcp_flag) {
        add_or(filter_exp, &first_condition_added);
        strcat(filter_exp, "(tcp");
        if (args->source_port > 0 || args->destination_port > 0) {
            strcat(filter_exp, " and (");
            if (args->source_port > 0) {
                char src_port_filter[64];
                sprintf(src_port_filter, "src port %d", args->source_port);
                strcat(filter_exp, src_port_filter);
                if (args->destination_port > 0) strcat(filter_exp, " or ");
            }
            if (args->destination_port > 0) {
                char dst_port_filter[64];
                sprintf(dst_port_filter, "dst port %d", args->destination_port);
                strcat(filter_exp, dst_port_filter);
            }
            strcat(filter_exp, ")");
        } else if (args->port > 0) {
            char port_filter[64];
            sprintf(port_filter, " and (port %d)", args->port);
            strcat(filter_exp, port_filter);
        }
        strcat(filter_exp, ")");
    }

    if (args->udp_flag) {
        add_or(filter_exp, &first_condition_added);
        strcat(filter_exp, "(udp");
        if (args->source_port > 0 || args->destination_port > 0) {
            strcat(filter_exp, " and (");
            if (args->source_port > 0) {
                char src_port_filter[64];
                sprintf(src_port_filter, "src port %d", args->source_port);
                strcat(filter_exp, src_port_filter);
                if (args->destination_port > 0) strcat(filter_exp, " or ");
            }
            if (args->destination_port > 0) {
                char dst_port_filter[64];
                sprintf(dst_port_filter, "dst port %d", args->destination_port);
                strcat(filter_exp, dst_port_filter);
            }
            strcat(filter_exp, ")");
        } else if (args->port > 0) {
            char port_filter[64];
            sprintf(port_filter, " and (port %d)", args->port);
            strcat(filter_exp, port_filter);
        }
        strcat(filter_exp, ")");
    }

    if (args->arp_flag) {
        add_or(filter_exp, &first_condition_added);
        strcat(filter_exp, "(arp)");
    }
    if (args->ndp_flag) {
       add_or(filter_exp, &first_condition_added);
         strcat(filter_exp, "((icmp6) and (icmp6[0] == 133 or icmp6[0] == 134 or icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137))");
    }
    if (args->icmp4_flag) {
         add_or(filter_exp, &first_condition_added);
        strcat(filter_exp, "(icmp)");
    }
    if (args->icmp6_flag) {
        add_or(filter_exp, &first_condition_added);
       strcat(filter_exp, "((icmp6) and (icmp6[0] == 128 or icmp6[0] == 129))");
    }
    if (args->igmp_flag) {
        add_or(filter_exp, &first_condition_added);
        strcat(filter_exp, "(igmp)");
    }
    if (args->mld_flag) {
       add_or(filter_exp, &first_condition_added);
        strcat(filter_exp, "(icmp6 and ip6[40] == 130)"); 
    }

    if (strlen(filter_exp) > 0) {
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
    } 
}



/**
 * @brief Main function for packet capturing.
 * @param args Pointer to the Arguments struct containing all infromation specified in arguments. 
 * Such as: protocol, port, number of packages etc.
 */
void main_sniffer(Arguments *args) {
    char errbuff[PCAP_ERRBUF_SIZE]; 
    bpf_u_int32 net; 
    bpf_u_int32 mask; 
    pcap_t *handle; 

    Pcap_lookupnet_checked(args->interface, &net, &mask, errbuff);
    handle = Pcap_open_live_checked(args->interface, 65535, 1, 1000, errbuff);
    apply_filters(handle, args, net);

    if (args->num_packages != 0) {
        pcap_loop(handle, args->num_packages, packet_handler, NULL);
    } else {
        printf("No packets requested to capture.\n");
        return;
    }

    pcap_close(handle);
}

/**
 * @brief Support function to printing byte_offset from a packet
 */
void print_hex_ascii_line(const unsigned char *bytes, int len, int offset) {
    int i;
    printf("0x%04x: ", offset);
    
   
    for (i = 0; i < 16; i++) {
        if (i < len) {
            if (i == 8) printf(" "); 
            printf("%02x ", bytes[i]);
        } else {
            printf("   "); 
        }
    }

    printf(" "); 

    for (i = 0; i < len; i++) {
        if (i == 8) printf(" "); 
        char ch = (bytes[i] >= 32 && bytes[i] <= 126) ? bytes[i] : '.';
        printf("%c", ch);
    }

    printf("\n");
}

/**
 * @brief Prints the byte offset 
 */
void byte_offset(const unsigned char *packet, int packet_length) {
    int row_offset = 0;

    while (row_offset < packet_length) {
        int row_length = 16;
        if (row_offset + row_length > packet_length) {
            row_length = packet_length - row_offset;
        }

        print_hex_ascii_line(packet + row_offset, row_length, row_offset);
        row_offset += 16;
    }
}


/**
 * @brief Handles each packet received by the sniffer.
 *
 * This function parses and prints information about each packet, including:
 * - timestamp: time
 * - src MAC: MAC address 
 * - dst MAC: MAC address 
 * - frame length: length
 * - src IP: IP address
 * - dst IP: IP address
 * - src port: port number 
 * - dst port: port number 
 * - byte_offset: byte_offset_hexa byte_offset_ASCII
 *
 * @param pkt_header Pointer to the packet header structure.
 * @param packet Pointer to the packet data.
 */
void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkt_header, const unsigned char *packet) {
    (void)user;
    const struct ether_header *eth_header;
    const struct ip *ip_header;
    const struct ip6_hdr *ip6_header;
    const struct tcphdr *tcp_header;
    const struct udphdr *udp_header;
    int size_ip;
    int size_ip6 = 40;  
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];

    // MAC SOURCE/DESTINATION VARIABLES
    const unsigned char *dst_mac = packet; 
    const unsigned char *src_mac = packet + 6; 

    // TIMESTAMP VARIABLES
    struct tm *ltime;
    char timestr[64];
    char tzoffset[16];
    time_t local_tv_sec;
    int milliseconds;


    // TIMESTAMP PRINT
    local_tv_sec = pkt_header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%Y-%m-%dT%H:%M:%S", ltime);
    milliseconds = (int)(pkt_header->ts.tv_usec / 1000);
    long gmtoff = ltime->tm_gmtoff; 
    int hours_offset = gmtoff / 3600;
    int minutes_offset = (gmtoff % 3600) / 60;
    snprintf(tzoffset, sizeof tzoffset, "%+03d:%02d", hours_offset, minutes_offset);
    printf("timestamp: %s.%03d%s\n", timestr, milliseconds, tzoffset);


    eth_header = (struct ether_header *) packet;


    // PRINT source and destination MAC addresses
    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);


    // PRINT LENGTH IN BYTES
    printf("frame length: %d bytes\n", pkt_header->len);


    // IP SOURCE AND IP DESTINATION PRINT
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
        ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

        printf("src IP: %s\n", src_ip);
        printf("dst IP: %s\n", dst_ip);
        if (ip6_header->ip6_nxt == IPPROTO_TCP) {
            // TCP
            tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + size_ip6);
            printf("src port: %d\n", ntohs(tcp_header->th_sport));
            printf("dst port: %d\n", ntohs(tcp_header->th_dport));
        } else if (ip6_header->ip6_nxt == IPPROTO_UDP) {
            // UDP 
            udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + size_ip6);
            printf("src port: %d\n", ntohs(udp_header->uh_sport));
            printf("dst port: %d\n", ntohs(udp_header->uh_dport));
        }
    } else { 
        ip_header = (struct ip*)(packet + sizeof(struct ether_header));
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        printf("src IP: %s\n", src_ip);
        printf("dst IP: %s\n", dst_ip);

        size_ip = ip_header->ip_hl * 4;

        if (ip_header->ip_p == IPPROTO_TCP) {
            // TCP
            tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + size_ip);
            printf("src port: %d\n", ntohs(tcp_header->th_sport));
            printf("dst port: %d\n", ntohs(tcp_header->th_dport));
        } else if (ip_header->ip_p == IPPROTO_UDP) {
            // UDP
            udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + size_ip);
            printf("src port: %d\n", ntohs(udp_header->uh_sport));
            printf("dst port: %d\n", ntohs(udp_header->uh_dport));
        }
    }

    // PRINT DATA FROM PACKET
    byte_offset(packet, pkt_header->caplen);
    
    // PRINT \n BEFORE THE NEXT PACKET FOR CLARITY OF READING
    printf("\n");
}

/**
 * @brief Stops the packet sniffing process.
 *
 */
void stop_sniffer() {
    if (handle != NULL) {
        pcap_breakloop(handle);
    }
}


/**
 * @brief wrapper for function pcap_lookupnet for better readability
 */
void Pcap_lookupnet_checked(const char *device, bpf_u_int32 *netp, bpf_u_int32 *maskp, char *errbuf) {
    if (pcap_lookupnet(device, netp, maskp, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device, errbuf);
        *netp = 0;
        *maskp = 0;
    }
}


/**
 * @brief wrapper for function pcap_open_live for better readability
 */
pcap_t *Pcap_open_live_checked(const char *device, int snaplen, int promisc, int to_ms, char *errbuf) {
    pcap_t *handle = pcap_open_live(device, snaplen, promisc, to_ms, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        exit(EXIT_FAILURE);
    }
    return handle;
}