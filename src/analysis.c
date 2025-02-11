#include <net/ethernet.h> // struct ether_header
#include "analysis.h"
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#define MAX_IPS 100
#define INITIAL_CAPACITY 100

pthread_mutex_t analysis_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t arp_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t url_mutex = PTHREAD_MUTEX_INITIALIZER;

// Struct to store IP address and number of SYN packets for that IP
struct ip_address {
    struct in_addr ip;
    int count;
};

//capacity of ip_list
int capacity = INITIAL_CAPACITY;

// Declares an array of ip_address structs. This holds the list of IPs and SYN counts
struct ip_address* ip_list; //Declare the pointer to the array

struct in_addr src_ip, dst_ip;


void init_ip_list() {
    ip_list = (struct ip_address *)malloc(MAX_IPS * sizeof(struct ip_address));
}

// Variable for ip_count, google_count, and bbc_count
int ip_count = 0;
int google_count = 0;
int bbc_count = 0;

// Declare a variable to hold the number of ARP responses
int arp_responses = 0;


void analyse_syn_packet(struct iphdr *ip_hdr, struct tcphdr *tcp_hdr) {
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

void analyse_url_packet(struct iphdr *ip_hdr, struct tcphdr *tcp_hdr, const unsigned char *packet) {
    if (tcp_hdr->dest == htons(80)) {
        // HTTP packet
        const char* payload = (const char*)(packet + sizeof(struct ether_header) +
                                            sizeof(struct iphdr) +
                                            sizeof(struct tcphdr));

        int payload_length = ntohs(ip_hdr->tot_len) - (ip_hdr->ihl * 4) - (tcp_hdr->doff * 4);

        // Create a null-terminated string from the payload
        char* payload_str = malloc(payload_length + 1);
        memcpy(payload_str, payload, payload_length);
        payload_str[payload_length] = '\0';

        if (strstr(payload_str, "www.google.co.uk")) {
            printf("============================\n");
            printf("Blacklisted URL violation detected\n");
            printf("Source IP: %s\n", inet_ntoa(src_ip));
            printf("Destination IP: %s (google)\n", inet_ntoa(dst_ip));
            printf("============================\n");

            google_count++;
        }

        if (strstr(payload_str, "www.bbc.co.uk")) {
            printf("============================\n");
            printf("Blacklisted URL violation detected\n");
            printf("Source IP: %s\n", inet_ntoa(src_ip));
            printf("Destination IP: %s (bbc)\n", inet_ntoa(dst_ip));  // Provide the missing argument
            printf("============================\n");

            bbc_count++;
        }

        free(payload_str);
    }
}

void analyse_arp_packet(const unsigned char *packet) {
    struct ether_arp *arp_hdr = (struct ether_arp *)(packet + sizeof(struct ether_header));

    if (ntohs(arp_hdr->ea_hdr.ar_op) == ARPOP_REPLY) {
        arp_responses++;
    }
}

void analyse(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {

    pthread_mutex_lock(&analysis_mutex);

    struct ether_header *eth_hdr = (struct ether_header *)packet;

    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
        struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
        
        src_ip.s_addr = ip_hdr->saddr;
        dst_ip.s_addr = ip_hdr->daddr;

        if (ip_hdr->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + sizeof(struct ether_header) +
                                                        sizeof(struct iphdr));

            analyse_url_packet(ip_hdr, tcp_hdr, packet);
            analyse_syn_packet(ip_hdr, tcp_hdr);
        }
    } else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
        analyse_arp_packet(packet);
    }

    pthread_mutex_unlock(&analysis_mutex);
}


void print_syn_summary() {

    pthread_mutex_lock(&analysis_mutex);

    char report[1024];

    int total_vios = bbc_count + google_count;
    int total_syn = 0;
    int unique_ips = 0;

    for (int i = 0; i < ip_count; i++) {
        total_syn += ip_list[i].count;
        if (ip_list[i].count > 0) {
            unique_ips++;
        }
    }

    snprintf(report, sizeof(report),  
    "==============================\n"
    "Intrusion Detection Report\n"
    "%d SYN packets detected from %d different IPs (syn attack)\n"
    "%d ARP responses (cache poisoning)\n"
    "%d URL Blacklist violations (%d google and %d bbc)\n"
    "==============================\n",
    total_syn, unique_ips, arp_responses, total_vios, google_count, bbc_count);

    write(1, report, strlen(report));

    pthread_mutex_unlock(&analysis_mutex); 
    free(ip_list); 

}