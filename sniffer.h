#include "arguments_parse.h"
#include <stdio.h>
#include <pcap.h>
#ifndef SNIFFER_H
#define SNIFFER_H


// Declaration of all Functions in Sniffer.c
void main_sniffer(Arguments *arguments);
void Pcap_lookupnet_checked(const char *device, bpf_u_int32 *netp, bpf_u_int32 *maskp, char *errbuf);
pcap_t *Pcap_open_live_checked(const char *device, int snaplen, int promisc, int to_ms, char *errbuf);
void apply_filters(pcap_t *handle, Arguments *args, bpf_u_int32 net);
void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkt_header, const unsigned char *packet);
void stop_sniffer();
void byte_offset(const unsigned char *packet, int packet_length);
void print_hex_ascii_line(const unsigned char *bytes, int len, int offset);
void add_or(char *filter_exp, int *first_condition_added);
void apply_filters(pcap_t *handle, Arguments *args, bpf_u_int32 net);
#endif