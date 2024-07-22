#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include "arguments_parse.h"


/**
 * @brief Lists all available network interfaces on the system that can be used for packet capturing.
 * if only -i or --interface or nothing in paramaters is specified
 */
void list_available_interfaces(void) {
    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return;
    }

    printf("Available interfaces:\n");
    for (device = alldevs; device != NULL; device = device->next) {
        printf("%s\n", device->name);
        if (device->description) {
            printf("\tDescription: %s\n", device->description);
        }
    }

    pcap_freealldevs(alldevs);
}


/**
 * @brief prints help message with all possible arguments, and show example of usage
 */
void print_help() {
    printf("Usage of the IPK Sniffer:\n");
    printf("  -i, --interface <interface>: Specify the interface to sniff on.\n");
    printf("  -p <port>: Filter packets by port.\n");
    printf("  --port-source <port>: Filter packets by source port.\n");
    printf("  --port-destination <port>: Filter packets by destination port.\n");
    printf("  -t, --tcp: Capture only TCP packets.\n");
    printf("  -u, --udp: Capture only UDP packets.\n");
    printf("  --arp: Capture only ARP packets.\n");
    printf("  --ndp: Capture only NDP packets.\n");
    printf("  --icmp4: Capture only ICMPv4 packets.\n");
    printf("  --icmp6: Capture only ICMPv6 packets.\n");
    printf("  --igmp: Capture only IGMP packets.\n");
    printf("  --mld: Capture only MLD packets.\n");
    printf("  -n <num>: Number of packets to capture.\n");
    printf("Example:\n");
    printf("  ./ipk-sniffer [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--ndp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}\n");
}



/**
 * @brief Parses command-line arguments.
 * @param argc The number of command-line arguments.
 * @param argv The array of command-line arguments.
 * @return A pointer to an Arguments Struct base  on the input arguments.
 * Returns NULL if help (-h or --help), or in case of an error (Invalid command)
 * or if listing available interfaces is the only operation(-i or --interface only , or without any arguments).
 */
Arguments *arguments_parse(int argc, char **argv) {


    // PRINT HELP MESSAGE
    if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        print_help();
        return NULL;
    }

    Arguments *args = malloc(sizeof(Arguments));
    if (!args) {
        fprintf(stderr, "Memory allocation failed.\n");
        return NULL;
    }

    // PRINT INTERFACE LIST
    if (argc == 1) {
        list_available_interfaces();
        if(args != NULL) {
            free(args);
        }
        return NULL;
    }

    // Initialize all fields to default values
    memset(args->interface, 0, MAX_LEN_IN);
    args->port = 0;
    args->destination_port = 0;
    args->source_port = 0;
    args->num_packages = 1; 
    args->tcp_flag = 0;
    args->udp_flag = 0;
    args->arp_flag = 0;
    args->ndp_flag = 0;
    args->icmp4_flag = 0;
    args->icmp6_flag = 0;
    args->igmp_flag = 0;
    args->mld_flag = 0;


    // Check for Specification without interface
    int interface_specified = 0;

    for (int i = 1; i < argc; i++) {
        // INTERFACE ARGUMENT
          if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0) {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                if (strlen(argv[i + 1]) < MAX_LEN_IN) {
                    strncpy(args->interface, argv[i + 1], MAX_LEN_IN - 1);
                    args->interface[MAX_LEN_IN - 1] = '\0'; 
                    i++;  
                    interface_specified = 1;
                } else {
                    return handle__argument_error(args, "Error: Interface name too long.");
                }
        }
        }
        // TCP ARGUMENT
        else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--tcp") == 0) {

            args->tcp_flag = 1;
        }
        // UDP ARGUMENT
        else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--udp") == 0) {
            args->udp_flag = 1;

        }
        // PORT ARGUMENT 
        else if (strcmp(argv[i], "-p") == 0 ||  strcmp(argv[i], "--port") == 0) {
            if (i + 1 < argc && isdigit(*argv[i+1])) {
                args->port = atoi(argv[i + 1]);
                // args->destination_port = args->port;
                // args->source_port = args->port;
                i++;
            } else {
                return handle__argument_error(args, "Error: Invalid or missing port number for -p option.");
            }
        } 
        // PORT DESTINATION ARGUMENT
        else if (strcmp(argv[i], "--port-destination") == 0) {
            if (i + 1 < argc && isdigit(*argv[i+1])) {
                args->destination_port = atoi(argv[i + 1]);
                i++;
            } else {
                return handle__argument_error(args, "Error: Invalid or missing port number for --port-destination option.");
            }

        }
        // PORT SOURCE ARGUMENT 
        else if (strcmp(argv[i], "--port-source") == 0) {
            if (i + 1 < argc && isdigit(*argv[i+1])) {
                args->source_port = atoi(argv[i + 1]);
                i++;
            } else {
                return handle__argument_error(args, "Error: Invalid or missing port number for --port-source option.");
            }

        }
        // ICMP4 ARGUMENT 
        else if (strcmp(argv[i], "--icmp4") == 0) {
            args->icmp4_flag = 1;
        }
        // ICMP6 ARGUMENT 
        else if (strcmp(argv[i], "--icmp6") == 0) {
            args->icmp6_flag = 1;
        }
        // ARP ARGUMENT 
        else if (strcmp(argv[i], "--arp") == 0) {
            args->arp_flag = 1;
        }
        // NDP ARGUMENT 
        else if (strcmp(argv[i], "--ndp") == 0) {
            args->ndp_flag = 1;
        }
        // IGMP ARGUMENT 
        else if (strcmp(argv[i], "--igmp") == 0) {
            args->igmp_flag = 1;
        }
        // MLD ARGUMENT 
        else if (strcmp(argv[i], "--mld") == 0) {
            args->mld_flag = 1;
        }
        // NUM OF PACKETS ARGUMENT 
        else if (strcmp(argv[i], "-n") == 0) {
            if (i + 1 < argc && isdigit(*argv[i + 1])) {
                args->num_packages = atoi(argv[i + 1]);
                i++;  
            } else {
                args->num_packages = 1; 
            }
        } else {
            // UNDEFINED ARGUMENT 
            fprintf(stderr, "Undefined command: %s\nWrite: ./ipk-sniffer -h OR ./ipk-sniffer --help to see all commands\n", argv[i]);
            if(args != NULL) {
                free(args);
            }
            exit(EXIT_FAILURE);
        }
    }


    // CHECK IF PORT HAS TCP/UDP 
    // OTHERWISE - ERROR
    if (args->port > 0 && !(args->tcp_flag || args->udp_flag)) {
        fprintf(stderr, "Error: Port specified without TCP or UDP flag.\n");
        if(args != NULL) {
            free(args); 
        }
        exit(EXIT_FAILURE);
    }
    
    // ARGUMENTS -i or --interface are specified without any interface
    if (!interface_specified && argc > 1) {
        list_available_interfaces();
        if(args != NULL) {
            free(args);
        }
        return NULL;
    }

    return args;
}


/**
 * @brief Handles errors related to argument parsing.
 * @param args Pointer to Arguments structure which may need to be freed.
 * @param error_message Error message to log to stderr.
 * @return NULL after freeing the provided Arguments structure, to indicate an error state.
 */
Arguments* handle__argument_error(Arguments *args, const char *error_message) {
    fprintf(stderr, "%s\n", error_message);
    if(args != NULL) {
        free(args);
    }
    return NULL;
}