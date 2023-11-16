#include <net/ethernet.h> // struct ether_header
#include "analysis.h"
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

//for now max number of ips we can store is 100
#define MAX_IPS 100

// Struct to store IP address and number of SYN packets for that IP
struct ip_address {
    struct in_addr ip;
    int count;
};

// Declares an array of ip_address structs. This holds the list of IPs and SYN counts
struct ip_address ip_list[MAX_IPS];
int ip_count = 0;

int arp_responses = 0;


void analyse(struct pcap_pkthdr *header, 
            const unsigned char *packet, 
            int verbose) {
    
    //Typecast packet contents to ether_header struct
    struct ether_header *eth_hdr = (struct ether_header *)packet;

    //Check if packet is an IP packet
    if (ntohs(eth_hdr->ether_type) == 2048) {
    
        //Typecast packet contents to iphdr struct (after skipping over ethernet header)
        struct iphdr *ip_hdr = (struct iphdr*)(packet + sizeof(struct ether_header));

        //Check if packet is a TCP packet
        if (ip_hdr->protocol == IPPROTO_TCP) {

            struct tcphdr *tcp_hdr = (struct tcphdr*)(packet + sizeof(struct ether_header) 
                                                + sizeof(struct iphdr));
                                              
            if (tcp_hdr->syn == 1 && tcp_hdr->ack == 0) { // SYN packet
        
                // Check if source IP already exists in ip_list
                int found = 0;
                for (int i = 0; i < ip_count; i++) {
                    if (ip_list[i].ip.s_addr == ip_hdr->saddr) {
                        ip_list[i].count++;
                        found = 1;
                        break;
                    }
                }
        
                // If IP not found, add it to the list
                if (!found) {
                    ip_list[ip_count].ip.s_addr = ip_hdr->saddr;
                    ip_list[ip_count].count = 1;
                    ip_count++;
                }
        
            }
      
        }

    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {

        struct ether_arp *arp_hdr = (struct ether_arp*)(packet + sizeof(struct ether_header));

        if (ntohs(arp_hdr->ea_hdr.ar_op) == ARPOP_REPLY) {

            arp_responses++;
        }

        


 
    }

}

// Print summary of SYN flood attack
void print_syn_summary() {
    
 

    int total_syn = 0;
    int unique_ips = 0;

    for (int i = 0; i < ip_count; i++) {
        total_syn += ip_list[i].count;
        if (ip_list[i].count > 0) {
            unique_ips++; 
        }
    }
// print_syn_summary()
printf("\n");
printf("==============================\n");
printf("SYN Flood Attack Detected\n");
printf("Total SYN Packets: %d\n", total_syn); 
printf("Unique Source IPs: %d\n", unique_ips);
printf("ARP Responses: %d\n", arp_responses);
printf("==============================\n");
//   printf("%d SYN packets detected from %d different IPs (syn attack)\n", total_syn, unique_ips);
}
}