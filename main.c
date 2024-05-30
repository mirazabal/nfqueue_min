#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "nf-queue.h"
#include <poll.h>


static int const NFQUEUE_NUM = 0;

void pkt_received(uint32_t queue, uint32_t id, uint32_t hash)
{
  if(queue != NFQUEUE_NUM)
    printf("Errro assigning the queue, just queue 0 working!!! \n");

  uint32_t const forward_pkt = 1;
  send_verdict_nfqueue(queue, id, forward_pkt);
}

int main()
{
  size_t const queue_num = 0;

  init_nfqueue(queue_num, &pkt_received);

  for(;;){
    poll(NULL,0, 1000000);
  }

  close_nfqueue(); 

  return 0;
}
