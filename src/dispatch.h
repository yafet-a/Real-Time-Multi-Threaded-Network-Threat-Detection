#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H
#define NUM_THREADS 5
#include <pcap.h>

void dispatch(const struct pcap_pkthdr *header, 
              const unsigned char *packet,
              int verbose);

extern pthread_t threadpool[NUM_THREADS];

void* worker(void* arg);

void init_threadpool();

#endif