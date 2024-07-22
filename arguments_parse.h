#include <stdio.h>
#ifndef ARGUMENTS_PARSE_H
#define ARGUMENTS_PARSE_H     


#define MAX_LEN_IN 256

typedef struct ARGUMENTS {
    char interface[MAX_LEN_IN];
    int port;
    int destination_port;
    int source_port;
    int num_packages;
    int tcp_flag;
    int udp_flag;
    int arp_flag;
    int ndp_flag;
    int icmp4_flag;
    int icmp6_flag;
    int igmp_flag;
    int mld_flag;
} Arguments;



// Declaration of functions
Arguments *arguments_parse(int argc, char **argv);
// Function list_available_interfaces, prints all available interfaces
void list_available_interfaces(void);
// Function print_help simply prints what every argument means and how to execute the program
void print_help();
// Handle Argument Errorr
Arguments* handle__argument_error(Arguments *args, const char *error_message);

#endif