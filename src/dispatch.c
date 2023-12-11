#include "analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <signal.h>
#include <pthread.h>


//number of threads and a thread ID variable globally
#define NUM_THREADS 2

pthread_t threads[NUM_THREADS];


pthread_cond_t cond = PTHREAD_COND_INITIALIZER;//condition variable for the queue
pthread_mutex_t queue_mutex=PTHREAD_MUTEX_INITIALIZER;//define a mutex for access to the queue

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;


//create a global work queue (I'll use a linked list here):
struct node {
  struct pcap_pkthdr *packet_header;
  const unsigned char *packet_data;
  int verbose;
  struct node* next; 
};

struct node* work_queue_head = NULL;
struct node* work_queue_tail = NULL;


// Worker thread function 
void* worker(void* arg) {

  // sigset_t set;
  // sigemptyset(&set);
  // sigaddset(&set, SIGINT);

  // pthread_sigmask(SIG_BLOCK, &set, NULL);

  while(1) {

    // Lock mutex before accessing queue
    pthread_mutex_lock(&queue_mutex);

    // Check if work items in queue  (process)
    while(work_queue_head == NULL) {
      printf("SLEEPING: Thread %ld is waiting for work\n", pthread_self());
      pthread_cond_wait(&cond, &queue_mutex);
    }
    printf("Thread %ld is processing a packet\n", pthread_self());


      // Get work item from head of queue to dequeue it
      struct node* item = work_queue_head;    
      work_queue_head = item->next;       

      if(work_queue_head == NULL) {
       work_queue_tail = NULL; 
      }



      // Unlock mutex before processing work item
      pthread_mutex_unlock(&queue_mutex);

      // Process work item (packet)
      analyse(item->packet_header, item->packet_data, item->verbose); 

      free(item);

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
  packet_item->next = NULL;

  // Add packet (node) to queue
  pthread_mutex_lock(&queue_mutex);  

  printf("Dispatching a packet to the queue\n");


  if(work_queue_tail == NULL) {
    work_queue_head = packet_item;
    work_queue_tail = packet_item;
  } else {
    work_queue_tail->next = packet_item;
    work_queue_tail = packet_item;
  }


  pthread_cond_broadcast(&cond);

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


}
