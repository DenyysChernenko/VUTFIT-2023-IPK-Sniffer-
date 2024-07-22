#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include "arguments_parse.h"
#include "sniffer.h"

void handle_sigint() {
    stop_sniffer();  
    exit(0); 

} 

int main(int argc, char *argv[]) {
    
    // Parsing Arguments and Save All the infromation in Struct Arguments
    Arguments *arguments = arguments_parse(argc, argv);
    signal(SIGINT, handle_sigint);


    // Check if any arguments was given
    if (arguments == NULL) {
        exit(0);
    }

    // Main Sniffer Logic
    main_sniffer(arguments);

    // Stop sniffer after processing all the packets or CTRL+C
    stop_sniffer();


    // Free arguments
    if(arguments != NULL) {
        free(arguments);
    }

    return 0;
}