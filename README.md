# Sniffer Documentation
## Denys Chernenko xchern08 IPK-2 ZETA
### Overview
Project ZETA is a network sniffer designed to capture and analyze network packets on a specific interface.


### Important Theory 
Theory, which is important to know, to understand the program functionality
- *`libcap`* 
- *IPv4 and IPv6* structures
- *TCP/UDP their strucutre, specifically ports*
- *ICMPv4,ICMPv6,ARP,NDP,IGMP,MLD* usage of these packets

 

## File Structure Overview
### Sniffer Review in Diagram
[![](https://mermaid.ink/img/pako:eNp9VU2L2zAQ_SvGJydkL23pwYdCoddCoce6iIk0tkVkSWiksGHJf-8oyofX8daXyO_NvPlU_FZLp7Bua2mA6IeGIcDU2c5W_FywagJtq7eC5GcEqwwK0oO2sdkU4jz3-B6GNKGNNHdjYww9SGwrikHb4UF5F2KbDR6QQoraQtTOihWaXAoS1xibJuFBHmBAWlBRetEbGBZwUqswhFXYrltrOfkvHxFfV4lhWlWajFrC5_cDgWt7uc5AOO_xjaFCNfwuLzq7TB1vnf_zd9M-hjSbA5NRjGh8wwZHp9XT1MU9OIbgQrOpVpWMpijgCNrAnr3us6cmq2anh_qiOrK67zHMy8obKK54rolmMZ8Spej83fiJ3Z8iCtf3hLGRzlKskuVNtqgqOUKotnl3kPvFKVflLAzaIY7vk56361UASa2F0RbXRXNUKposVg4liWdVUEpwY4tjrw13TuCrL04MBO4sB1H6cjfYGtWKiPfmJIo3NV6CF-xcZrib3c9t7uau2vtepDylz58qu5bUr6zgPFou8ohCjsidUddiS6oKj1piSZMs-HuhPrhJkywv0YmJAxYXXqF96nO0kuEinnHukDzn899489y3bOwX0AR08M8RF6Msky4NCs1ifIkwsMIlON-gJGNJ2B_iqPLOHPIagHpYrS7V09rfdrt6efm2uNWFfAzqI4u7-3XjO1vv6gkD44r_1S-XqKvjiBN2dctHhT0kE7u6s2c2hRTd75OVdct14a5OXkHE63egbnswxCjytrnw8_qlyD_nf-GxCxI?type=png)](https://mermaid.live/edit#pako:eNp9VU2L2zAQ_SvGJydkL23pwYdCoddCoce6iIk0tkVkSWiksGHJf-8oyofX8daXyO_NvPlU_FZLp7Bua2mA6IeGIcDU2c5W_FywagJtq7eC5GcEqwwK0oO2sdkU4jz3-B6GNKGNNHdjYww9SGwrikHb4UF5F2KbDR6QQoraQtTOihWaXAoS1xibJuFBHmBAWlBRetEbGBZwUqswhFXYrltrOfkvHxFfV4lhWlWajFrC5_cDgWt7uc5AOO_xjaFCNfwuLzq7TB1vnf_zd9M-hjSbA5NRjGh8wwZHp9XT1MU9OIbgQrOpVpWMpijgCNrAnr3us6cmq2anh_qiOrK67zHMy8obKK54rolmMZ8Spej83fiJ3Z8iCtf3hLGRzlKskuVNtqgqOUKotnl3kPvFKVflLAzaIY7vk56361UASa2F0RbXRXNUKposVg4liWdVUEpwY4tjrw13TuCrL04MBO4sB1H6cjfYGtWKiPfmJIo3NV6CF-xcZrib3c9t7uau2vtepDylz58qu5bUr6zgPFou8ohCjsidUddiS6oKj1piSZMs-HuhPrhJkywv0YmJAxYXXqF96nO0kuEinnHukDzn899489y3bOwX0AR08M8RF6Msky4NCs1ifIkwsMIlON-gJGNJ2B_iqPLOHPIagHpYrS7V09rfdrt6efm2uNWFfAzqI4u7-3XjO1vv6gkD44r_1S-XqKvjiBN2dctHhT0kE7u6s2c2hRTd75OVdct14a5OXkHE63egbnswxCjytrnw8_qlyD_nf-GxCxI)

## Short Brief About Implementation
### 1. `main.c`
- **Description**: The main entry point of the program.
- **Functionality**: Initiates the program by parsing command-line arguments using `arguments_parse.c` and starts packet capture using `sniffer.c`.
- **Interactions**: Calls function `arguments_parse` from `arguments_parse.c` to create the `Arguments` structure and then calls the `main_sniffer` function from `sniffer.c`.

### 2. `arguments_parse.c`
- **Description**: Contains logic for parsing command-line arguments.
- **Functionality**: Parses command-line arguments to create an `Arguments` structure containing information required for packet capture.
- **Interactions**: Used by `main.c` to parse command-line arguments and create the `Arguments` structure.

### 3. `arguments_parse.h`
- **Description**: Header file containing declarations for functions and structures in `arguments_parse.c`.
- **Functionality**: Provides declarations for functions and structure used for parsing command-line arguments.
- **Interactions**: Included by `main.c`, `arguments_parse.c` and `sniffer.h`to ensure consistency in function declarations and have an opportunity to use `Arguments` struct.

### 4. `sniffer.c`
- **Description**: Contains the main logic for capturing packets.
- **Functionality**: Implements packet capture functionality based on the information provided in the `Arguments` structure.
- **Interactions**: Called by `main.c` to initiate packet capture and filter packets based on specified criteria.

### 5. `sniffer.h`
- **Description**: Header file containing declarations for functions and structures in `sniffer.c`.
- **Functionality**: Provides declarations for functions.
- **Interactions**: Included by `sniffer.c`.

### Important Information about the `Arguments` Struct

The `Arguments` struct is crucial for configuring and controlling the behavior of the network sniffer. It contains the following fields:
1. `interface`: A character array to store the name of the network interface to sniff on. 
2. `port`: An integer representing the port number used for filtering packets based on port number.
3. `destination_port`: An integer representing the destination port number used for filtering packets.
4. `source_port`: An integer representing the source port number used for filtering packets.
5. `num_packages`: An integer specifying the number of packets to capture.
6. `tcp_flag`: A flag (0 or 1) indicating whether to capture only TCP packets.
7. `udp_flag`: A flag (0 or 1) indicating whether to capture only UDP packets.
8. `arp_flag`: A flag (0 or 1) indicating whether to capture only ARP packets.
9. `ndp_flag`: A flag (0 or 1) indicating whether to capture only NDP packets.
10. `icmp4_flag`: A flag (0 or 1) indicating whether to capture only ICMPv4 packets.
11. `icmp6_flag`: A flag (0 or 1) indicating whether to capture only ICMPv6 packets.
12. `igmp_flag`: A flag (0 or 1) indicating whether to capture only IGMP packets.
13. `mld_flag`: A flag (0 or 1) indicating whether to capture only MLD packets.

<i>Also Shown In Diagram</i>

### File Structure Summary
The file structure is organized to separate concerns and maintain modularity. Each file focuses on a specific aspect of the program, such as argument parsing or packet capture, making the codebase easier to understand and maintain.







## Usage
To use Sniffer Correctly follow these steps:
**Main Logic**
- **-i or --interface**: Specifies the network interface to sniff packets from.
  - **Value**: User-provided.
  - **Meaning or expected program behavior**: Indicates the network interface from which the sniffer will capture packets.

- **-p or --port**: Specifies the port number for filtering TCP/UDP packets.
  - **Value**: User-provided.
  - **Meaning or expected program behavior**: Filters TCP/UDP packets based on the specified port number.

- **--port-source**: Specifies the source port number for filtering TCP/UDP packets.
  - **Value**: User-provided.
  - **Meaning or expected program behavior**: Filters TCP/UDP packets based on the source port number.

- **--port-destination**: Specifies the destination port number for filtering TCP/UDP packets.
  - **Value**: User-provided.
  - **Meaning or expected program behavior**: Filters TCP/UDP packets based on the destination port number.

- **--tcp or -t**: Specifies the display of TCP segments.
  - **Meaning or expected program behavior**: Indicates whether to display TCP segments.

- **--udp or -u**: Specifies the display of UDP datagrams.
  - **Meaning or expected program behavior**: Indicates whether to display UDP datagrams.

- **--arp**: Specifies the display of ARP frames.
  - **Meaning or expected program behavior**: Indicates whether to display ARP frames.

- **--ndp**: Specifies the display of NDP packets (subset of ICMPv6).
  - **Meaning or expected program behavior**: Indicates whether to display NDP packets.

- **--icmp4**: Specifies the display of only ICMPv4 packets.
  - **Meaning or expected program behavior**: Indicates whether to display only ICMPv4 packets.

- **--icmp6**: Specifies the display of only ICMPv6 echo request/response.
  - **Meaning or expected program behavior**: Indicates whether to display only ICMPv6 echo request/response.

- **--igmp**: Specifies the display of IGMP packets.
  - **Meaning or expected program behavior**: Indicates whether to display IGMP packets.

- **--mld**: Specifies the display of MLD packets 
  - **Meaning or expected program behavior**: Indicates whether to display MLD packets.
- **-n**: Specifies number of packets to display
   -  **Meaning or expected program behavior**: Indicates how many packets to display.
- **-h or --help**: Print Support Help Information
    - **Meaning or expected program behavior**: Print all information about arguments, and example of usage
### Example of Usage: 

`sudo ./ipk-sniffer -i any --port-source  3333 -t`

 **OR**

`./ipk-sniffer -i any --port-source  3333 -t`

## Testing
### Objective
The objective of this testing session is to verify the functionality and correctness of the Sniffer under various scenarios.

### Test Environment
- Operating System: Linux Ubuntu 20.04
- Network Interface: eth0, lo

### Test Cases (Packets)

#### Case 1: Basic Packet Capture
- **Description**: Verify that the sniffer can capture packets from the specified network interface (eth0).
- **Steps**:
  1. Run the sniffer with the command: `./ipk-sniffer -i eth0`
  2. Generate network traffic from another device on the network and check for correct packets with WireShark.
- **Expected Result**: The sniffer should capture packets and display their details including timestamp, source and destination MAC addresses, IP addresses, and ports.
##### Case 1 Overview
 - **Input** `./ipk-sniffer -i eth0`
 - **Output in Terminal** 
`timestamp: 2024-04-21T17:17:02.050+02:00`
`src MAC: 00:15:5d:0c:b0:31`
`dst MAC: 01:00:5e:7f:ff:fa`
`frame length: 216 bytes`
`src IP: 172.28.64.1`
`dst IP: 239.255.255.250`
`src port: 49736`
`dst port: 1900`
`0x0000: 01 00 5e 7f ff fa 00 15  5d 0c b0 31 08 00 45 00  ..^..... ]..1..E.`
`0x0010: 00 ca 00 79 00 00 01 11  dc 92 ac 1c 40 01 ef ff  ...y.... ....@...`
`0x0020: ff fa c2 48 07 6c 00 b6  57 04 4d 2d 53 45 41 52  ...H.l.. W.M-SEAR`
`0x0030: 43 48 20 2a 20 48 54 54  50 2f 31 2e 31 0d 0a 48  CH * HTT P/1.1..H`
`0x0040: 4f 53 54 3a 20 32 33 39  2e 32 35 35 2e 32 35 35  OST: 239 .255.255`
`0x0050: 2e 32 35 30 3a 31 39 30  30 0d 0a 4d 41 4e 3a 20  .250:190 0..MAN:`
`0x0060: 22 73 73 64 70 3a 64 69  73 63 6f 76 65 72 22 0d  "ssdp:di scover".`
`0x0070: 0a 4d 58 3a 20 31 0d 0a  53 54 3a 20 75 72 6e 3a  .MX: 1.. ST: urn:`
`0x0080: 64 69 61 6c 2d 6d 75 6c  74 69 73 63 72 65 65 6e  dial-mul tiscreen`
`0x0090: 2d 6f 72 67 3a 73 65 72  76 69 63 65 3a 64 69 61  -org:ser vice:dia`
`0x00a0: 6c 3a 31 0d 0a 55 53 45  52 2d 41 47 45 4e 54 3a  l:1..USE R-AGENT:`
`0x00b0: 20 47 6f 6f 67 6c 65 20  43 68 72 6f 6d 65 2f 31   Google  Chrome/1`
`0x00c0: 32 34 2e 30 2e 36 33 36  37 2e 36 30 20 57 69 6e  24.0.636 7.60 Win`
`0x00d0: 64 6f 77 73 0d 0a 0d 0a                          dows....`
 - **Output in WireShark** 
  Absolutely the same, so my sniffer in terminal captured the packet correct.


#### Case 2: UDP Packet Filtering
- **Description**: Verify that the sniffer can filter and display UDP packets based on specified criteria.
- **Steps**:
  1. Run the sniffer with the command: `./ipk-sniffer -i eth0 -u -p 2222`
  2. Generate UDP traffic from a device with source port 2222 and message Hello, Worldss!.
- **Expected Result**: The sniffer should capture and display only UDP packets with a source port of 2222.
##### Case 2 Overview
 - **Input** `./ipk-sniffer -i eth0 -u -p 2222`
 - **Output in Terminal** 
`timestamp: 2024-04-21T17:20:46.120+02:00`
`src MAC: 00:00:00:00:00:00`
`dst MAC: 00:00:03:04:00:06`
`frame length: 60 bytes`
`src IP: 97.136.127.0`
`dst IP: 0.1.127.0`
`src port: 38981`
`dst port: 2222`
`0x0000: 00 00 03 04 00 06 00 00  00 00 00 00 00 00 08 00  ........ ........`
`0x0010: 45 00 00 2c db 36 40 00  40 11 61 88 7f 00 00 01  E..,.6@. @.a.....`
`0x0020: 7f 00 00 01 8b 6b 08 ae  00 18 fe 2b 48 65 6c 6c  .....k.. ...     +Hell`
`0x0030: 6f 2c 20 73 6e 69 66 66  65 72 21 0a               o, World ss!.`
 - **Output in WireShark**  
  Absolutely the same, so sniffer in terminal captured the packet correct.

#### Case 3: ICMP6  Packet Filtering
- **Description**: Verify that the sniffer can filter and display Icmp6 packets based on specified criteria.
- **Steps**:
  1. Run the sniffer with the command: `./ipk-sniffer -i any --icmp6`
  2. Generate Icmp6 traffic from another device.
- **Expected Result**: The sniffer should capture and display only ICMP6 packet.
##### Case 3 Overview 
 - **Input** `./ipk-sniffer -i any --icmp6`
 - **Output in Terminal** 
`timestamp: 2024-04-21T17:25:31.026+02:00`
`src MAC: 00:00:00:00:00:00`
`dst MAC: ff:ff:ff:ff:ff:ff`
`frame length: 73 bytes`
`src IP: ::1`
`dst IP: ::1`
`src port: 38981`
`dst port: 2222`
`0x0000: ff ff ff ff ff ff 00 00  00 00 00 00 86 dd 60 00  ........ .......`
`0x0010: 00 00 00 13 3a 40 00 00  00 00 00 00 00 00 00 00  ....:@.. ........`
`0x0020: 00 00 00 00 00 01 00 00  00 00 00 00 00 00 00 00  ........ ........`
`0x0030: 00 00 00 00 00 01 80 00  7b 37 00 00 00 00 48 65  ........ {7....He`
`0x0040: 6c 6c 6f 20 49 50 76 36  21                       llo IPv6 !`
 - **Output in WireShark**  
  Absolutely the same, so sniffer in terminal captured the packet correct.


### Test Cases (Parsing Arguments)



#### Case 1: Basic Argument Parsing
- **Description**: Verify that sniffer parse basic case correctly.
- **Steps**:
  1. Run the sniffer with the command: `./ipk-sniffer -i eth0`
  2. Not see the erorr and process the packets.
- **Expected Result**: The sniffer should capture packets and display their details including timestamp, source and destination MAC addresses, IP addresses, and ports without any errors in arguments level.
##### Case 1 Overview
 - **Input** `./ipk-sniffer -i eth0`
 - **Output in Terminal** `Captured Packet`
 - **Result** Everything is correct , and no error message is printed

 #### Case 2: Error in Argument Command-Line
- **Description**: Verify that sniffer arguments parsing is captures an error (Undefined command).
- **Steps**:
  1. Run the sniffer with the command: `./ipk-sniffer -inteasdawadaw eth0`
  2. See the Error Message in `STDERR`.
- **Expected Result**: The Error Message in Terminal(`STDERR`), and `Return Code -1`.
##### Case 2 Overview
 - **Input** `./ipk-sniffer -inteasdawadaw eth0`
 - **Output in Terminal** `Undefined command: -inteasdawadaw
Write: ./ipk-sniffer -h OR ./ipk-sniffer --help to see all commands`
 - **Result** Everything is correct , and error message is printed

 #### Case 3: Correct Number of Packets
 - **Description**: Verify that sniffer arguments parsing is correctly verify number of packets.
- **Steps**:
  1. Run the sniffer with the command: `./ipk-sniffer -i eth0 -n 10`
  2. See the 10 packets in terminal after some time.
- **Expected Result**: Wait for a while, and see the 10 packets from eth0 in a terminal.
##### Case 3 Overview
 - **Input** `./ipk-sniffer -i eth0 -n 10`
 - **Output in Terminal** `Captured 10 packets from eth0`
 - **Result** Everything is correct , and Argument Command-Line is correct parsed and number of packets assigned correctly.


## Bibliography
Ubuntu. *Ubuntu Homepage* [online]. Version 20.04 LTS. Canonical Ltd., 2020. [Accessed April 13, 2024]. Available at: [https://ubuntu.com/](https://ubuntu.com/).
Wireshark. *Wireshark - Go Deep.* [online]. Version 3.4.6. Wireshark Foundation, 2021. [Accessed April 13, 2024]. Available at: [https://www.wireshark.org/](https://www.wireshark.org/).
libpcap. *libpcap - Wikipedia* [online]. Wikimedia Foundation, Ongoing. [Accessed April 11, 2024]. Available at: [https://en.wikipedia.org/wiki/libpcap](https://en.wikipedia.org/wiki/libpcap).
