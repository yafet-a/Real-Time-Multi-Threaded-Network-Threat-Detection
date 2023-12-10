#include "analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <signal.h>
#include <pthread.h>


//number of threads and a thread ID variable globally
#define NUM_THREADS 4 
pthread_t threads[NUM_THREADS];


//create a global work queue (I'll use a linked list here):
struct node {
  struct pcap_pkthdr *packet_header;
  const unsigned char *packet_data;
  int verbose;
  struct node* next; 
};

struct node* work_queue_head = NULL;
struct node* work_queue_tail = NULL;


//define a mutex for access to the queue
pthread_mutex_t queue_mutex;


// Worker thread function 
void* worker(void* arg) {

  while(1) {

    // Lock mutex before accessing queue
    pthread_mutex_lock(&queue_mutex);

    // Check if work items in queue  
    if(work_queue_head != NULL) {

      // Get work item from head of queue  
      struct node* item = work_queue_head;    

      // Remove from queue  
      work_queue_head = item->next;       

      if(work_queue_head == NULL) {
       work_queue_tail = NULL; 
      }

      pthread_mutex_unlock(&queue_mutex);

      // Process work item (packet)
      analyse(item->packet_header, item->packet_data, item->verbose); 


    } else {
      // Unlock mutex if no work items   
      pthread_mutex_unlock(&queue_mutex);
    }

  } 
   

}

void dispatch(struct pcap_pkthdr *header,
              const unsigned char *packet,
              int verbose) {

  // Allocate node
  struct node* packet_item = malloc(sizeof(struct node));

  // Set packet in node  
  packet_item->packet_header = header;
  packet_item->packet_data = packet; 
  packet_item->verbose = verbose;

  // Add node to queue
  pthread_mutex_lock(&queue_mutex);  

  if(work_queue_tail == NULL) {
    work_queue_head = packet_item;
    work_queue_tail = packet_item;
  } else {
    work_queue_tail->next = packet_item;
    work_queue_tail = packet_item;
  }

  free(packet_item);
  pthread_mutex_unlock(&queue_mutex);



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
  free(ptr);
  // TODO: Your part 2 code here
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded.
  analyse(header, packet, verbose);



}
