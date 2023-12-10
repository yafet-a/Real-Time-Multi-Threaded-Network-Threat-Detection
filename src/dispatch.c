#include "analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <signal.h>



void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {
              
              int* ptr;
              int size = 1;
              ptr = (int*)malloc(size * sizeof(int));
              if (ptr == NULL){
                printf("Error");
              }
              else{

                for(int i =0; i<size; ++i){
                  ptr[i] = i + 1;
                }
              
              }
            
  // TODO: Your part 2 code here
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded.
  analyse(header, packet, verbose);


}
