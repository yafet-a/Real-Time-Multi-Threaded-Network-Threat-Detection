#include <net/ethernet.h> // struct ether_header
#include "analysis.h"
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>

// Define MAX_IPS 
#define MAX_IPS 100


#define INITIAL_CAPACITY 100

// Struct to store IP address and number of SYN packets for that IP
struct ip_address {
    struct in_addr ip;
    int count;
};

//capacity of ip_list
int capacity = INITIAL_CAPACITY;

// Declares an array of ip_address structs. This holds the list of IPs and SYN counts

struct ip_address* ip_list;

struct in_addr src_ip, dst_ip;


void init() {
    ip_list = (struct ip_address *)malloc(MAX_IPS * sizeof(struct ip_address));
}

// Variable for ip_count, google_count, and bbc_count
int ip_count = 0;
int google_count = 0;
int bbc_count = 0;

// Declare a variable to hold the number of ARP responses
int arp_responses = 0;

void analyse(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {

    // Typecast packet contents to ether_header struct
    struct ether_header *eth_hdr = (struct ether_header *)packet;

    // Check if packet is an IP packet
    if (ntohs(eth_hdr->ether_type) == 2048) {

        // Typecast packet contents to iphdr struct (after skipping over the ethernet header)
        struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

        src_ip.s_addr = ip_hdr->saddr;
        dst_ip.s_addr = ip_hdr->daddr;

        // Check if packet is a TCP packet
        if (ip_hdr->protocol == IPPROTO_TCP) {

            struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) +
                                                        sizeof(struct iphdr));

            // Check port 80 for URLs
            if (tcp_hdr->dest == htons(80)) {

                // HTTP packet
                char *payload = (char *)(packet + sizeof(eth_hdr) +
                                         sizeof(ip_hdr) + sizeof(tcp_hdr));

                if (strstr(payload, "Host: www.google.co.uk")) {
                    printf("Blacklisted URL: google\n");
                    google_count++;
                } else if (strstr(payload, "www.bbc.co.uk")) {
                    printf("Blacklisted URL: bbc\n");
                    bbc_count++;
                }
            }

            // Check if packet is a SYN packet
            if (tcp_hdr->syn == 1 && tcp_hdr->ack == 0) {
                int found = 0;
                for (int i = 0; i < ip_count; i++) {
                    if (ip_list[i].ip.s_addr == ip_hdr->saddr) {
                        found = 1;
                        // Increment count for existing IP
                        ip_list[i].count++;
                        break;
                    }
                }

                if (!found) {
                    // Add new IP
                    if (ip_count < capacity) {
                        ip_list[ip_count].ip.s_addr = ip_hdr->saddr;
                        ip_list[ip_count].count = 1;
                        ip_count++;
                    } else {
                        // Expand the array if needed
                        capacity *= 2;
                        // allocate new array with double capacity
                        struct ip_address *new_ip_list = realloc(ip_list, capacity * sizeof(struct ip_address));

                        if (new_ip_list == NULL) {
                            // Handle memory allocation failure
                            exit(EXIT_FAILURE);
                        }

                        ip_list = new_ip_list;

                        // Add new IP
                        ip_list[ip_count].ip.s_addr = ip_hdr->saddr;
                        ip_list[ip_count].count = 1;
                        ip_count++;
                    }
                }
            }
        }
    } else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
        struct ether_arp *arp_hdr = (struct ether_arp *)(packet + sizeof(struct ether_header));

        if (ntohs(arp_hdr->ea_hdr.ar_op) == ARPOP_REPLY) {
            arp_responses++;
        }
    }
}


// Print summary of SYN flood attack
void print_syn_summary() {
    int total_vios = bbc_count + google_count;
    int total_syn = 0;
    int unique_ips = 0;

    for (int i = 0; i < ip_count; i++) {
        total_syn += ip_list[i].count;
        if (ip_list[i].count > 0) {
            unique_ips++;
        }
    }

    printf("\n");
    printf("==============================\n");
    printf("SYN Flood Attack Detected\n");
    printf("Total SYN Packets: %d\n", total_syn);
    printf("Unique Source IPs: %d\n", unique_ips);
    printf("ARP Responses: %d (cache poisoning)\n", arp_responses);  
    printf("Source IP: %s\n", inet_ntoa(src_ip));  
    printf("%d URL blacklist violations (%d google, %d bbc)\n", total_vios, google_count, bbc_count);
    printf("==============================\n");

}