#ifndef MIB_NFQUEUE
#define MIB_NFQUEUE

#include <stdint.h>

void init_nfqueue(unsigned int queue_num,void(*add_packet_sched_cb)(uint32_t,uint32_t,uint32_t));
void send_verdict_nfqueue(uint32_t queue_num, uint32_t id, uint32_t packetDecision);
void close_nfqueue();

#endif

