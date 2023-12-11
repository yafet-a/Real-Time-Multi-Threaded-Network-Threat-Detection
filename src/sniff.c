#include "sniff.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include "analysis.h"
#include "dispatch.h"
#include <pthread.h>
#include <unistd.h> // for sleep()

//global flag to indicate when threads are done
int threads_done = 0;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

  int verbose = *(int*)args;
  
  if(verbose) {
    dump(packet, header->len);
  }

  dispatch(header, packet, verbose);  
}
void init_ip_list();

void print_syn_summary(void);

// Signal handler 
void sigint_handler(int signum) {
  threads_done = 1;
  // while(!threads_done){ //wait for threads to finish
  //   sleep(1);
  // }
  print_syn_summary();
  exit(0);
}

void cleanup_threads(){
  for(int i = 0; i < NUM_THREADS; i++) {
  pthread_join(threadpool[i], NULL);
  }
}

// Application main sniffing loop
void sniff(char *interface, int verbose) {


  char errbuf[PCAP_ERRBUF_SIZE];

  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
  pcap_t *pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }
  

    //create the threads
  for(int i = 0; i < NUM_THREADS; i++) {  
    printf("Creating thread %d\n", i);
    pthread_create(&threadpool[i], NULL, worker, NULL);
  }

  
  // Register signal handler
  signal(SIGINT, sigint_handler);
  init_ip_list();
  

  // struct pcap_pkthdr header;
  // const unsigned char *packet;

  // Capture packet one packet everytime the loop runs using pcap_next(). This is inefficient.
  // A more efficient way to capture packets is to use use pcap_loop() instead of pcap_next().
  // See the man pages of both pcap_loop() and pcap_next().
  
  int ret;
  ret = pcap_loop(pcap_handle, -1, got_packet, (u_char*)&verbose);  
  if (ret < 0) {
      
  fprintf(stderr, "Error from pcap_loop: %s\n", pcap_geterr(pcap_handle));
      exit(1);
  }

  if (pcap_handle != NULL){
    // Join threads to wait for completion
    cleanup_threads();
    pcap_close(pcap_handle);

    }

// pcap_cleanup(pcap_handle);

//set threads_done to true
    threads_done = 1;

}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}