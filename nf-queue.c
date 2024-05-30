#include "nf-queue.h"
//#include "hash_function.h"
//#include "mib_time.h"

#include <pthread.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
     
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
    
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/netfilter/nfnetlink_queue.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
    
/* only for NFQA_CT, not needed otherwise: */
#include <linux/netfilter/nfnetlink_conntrack.h>



#define BUFFER_SIZE 256

static struct mnl_socket *nl;
static pthread_t thread_nfqueue;
static void(*add_packet_sched_cb)(uint32_t,uint32_t,uint32_t);

static struct nlmsghdr* nfq_hdr_put(char *buf, int type, uint32_t queue_num)
{
  struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
  nlh->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | type;
  nlh->nlmsg_flags = NLM_F_REQUEST;

  struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
  nfg->nfgen_family = AF_UNSPEC;
  nfg->version = NFNETLINK_V0;
  nfg->res_id = htons(queue_num);

  return nlh;
}
    
void send_verdict_nfqueue(uint32_t queue_num, uint32_t id, uint32_t packetDecision)
{
  char buf[MNL_SOCKET_BUFFER_SIZE];
  struct nlmsghdr *nlh;
  struct nlattr *nest;

  nlh = nfq_hdr_put(buf, NFQNL_MSG_VERDICT, queue_num);
  //nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);
  nfq_nlmsg_verdict_put(nlh, id, packetDecision);

  /* example to set the connmark. First, start NFQA_CT section: */
  nest = mnl_attr_nest_start(nlh, NFQA_CT);

  /* then, add the connmark attribute: */
  mnl_attr_put_u32(nlh, CTA_MARK, htonl(42));
  /* more conntrack attributes, e.g. CTA_LABEL, could be set here */

  /* end conntrack section */
  mnl_attr_nest_end(nlh, nest);

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
    perror("mnl_socket_send");
    exit(EXIT_FAILURE);
  }
}


static void print_ip_info(struct iphdr* ipHeader)
{
//	unsigned char* payloadData = (unsigned char*)mnl_attr_get_payload(attr[NFQA_PAYLOAD]);
	struct in_addr ip_addr;
  ip_addr.s_addr = ipHeader->saddr;
	char* ip_saddr =  inet_ntoa(ip_addr);
  printf("The IP address source is %s\n",ip_saddr);
  ip_addr.s_addr = ipHeader->daddr;
	char* ip_daddr =  inet_ntoa(ip_addr);
	printf("The IP address destination = %s\n", ip_daddr);
	printf("Total length %u \n", (unsigned int)ipHeader->tot_len);
}


//static void add_ip_addr( struct iphdr* ipHeader, char* buffer)
//{
//  struct in_addr ip_addr;
//
//  ip_addr.s_addr = ipHeader->saddr;
//  char* ip_saddr =  inet_ntoa(ip_addr);
//
//  ip_addr.s_addr = ipHeader->daddr;
//  char* ip_daddr =  inet_ntoa(ip_addr);
//
//  strncpy(buffer, ip_saddr, BUFFER_SIZE);
//  strncat(buffer, ip_daddr, 25);
//}
//
//
//static void add_tcp_ports( struct iphdr* ip_header, char* buffer)
//{
//	struct tcphdr* tcp_header= (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl); //this fixed the problem
//
//	unsigned int sport = htons((unsigned short int) tcp_header->source); //sport now has the source port
//	unsigned int dport = htons((unsigned short int) tcp_header->dest);   //dport now has the dest port
//
//  char str_s[25];
//  char str_d[25];
//
//	sprintf(str_s, "%u", sport);
//	sprintf(str_d, "%u", dport);
//
//	strncat(buffer, str_s, sizeof(str_s));
//	strncat(buffer, str_d, sizeof(str_d));
//}
//
//static uint32_t create_hash(struct iphdr* ipHeader, uint32_t id)
//{
//  if (ipHeader->protocol == IPPROTO_ICMP){
//    printf("ICMP packet detected... \n");
//    return 0;
//  }
//
//	if (ipHeader->protocol == IPPROTO_UDP){
//    printf("UDP Packet with id = %d, inserted into UPF at timestamp = %ld \n", id, mib_get_time_us() ); 
//    return 0;
//  }
//  // lets see if it does better...
//  return 1;
//
//  char buffer[BUFFER_SIZE];
//  add_ip_addr(ipHeader,buffer);
//
//  if (ipHeader->protocol == IPPROTO_TCP){
//    add_tcp_ports(ipHeader,buffer);
//  }
//  //printf("Buffer before hashing = %s \n", buffer);
//  return jenkins_one_at_a_time_hash(buffer, strlen(buffer));
//}
//

static int queue_cb(const struct nlmsghdr *nlh, void *data)
  {
    struct nlattr *attr[NFQA_MAX+1] = {};

    if (nfq_nlmsg_parse(nlh, attr) < 0) {
      perror("problems parsing");
      return MNL_CB_ERROR;
    }
    if (attr[NFQA_PACKET_HDR] == NULL) {
      fputs("metaheader not set\n", stderr);
      return MNL_CB_ERROR;
    }

    uint16_t plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);

  //	if (attr[NFQA_CAP_LEN]) {
    //	uint32_t orig_len = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));
  //		if (orig_len != plen)
  //			printf("truncated ");
  //	}

  //	uint32_t skbinfo = attr[NFQA_SKB_INFO] ? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;
  //	if (skbinfo & NFQA_SKB_GSO)
  //		printf("GSO ");

    struct nfqnl_msg_packet_hdr* ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);
    uint32_t id = ntohl(ph->packet_id);
    printf("packet received (id=%u hw=0x%04x hook=%u, payload len %u",
      id, ntohs(ph->hw_protocol), ph->hook, plen);

  /*
   * ip/tcp checksums are not yet valid, e.g. due to GRO/GSO.
   * The application should behave as if the checksums are correct.
   *
   * If these packets are later forwarded/sent out, the checksums will
   * be corrected by kernel/hardware.
   */
  //	if (skbinfo & NFQA_SKB_CSUMNOTREADY)
  //		printf(", checksum not ready");
  //	puts(")");

  //	nfq_send_verdict(ntohs(nfg->res_id), id);

    struct nfgenmsg* nfg = mnl_nlmsg_get_payload(nlh);
    

    struct iphdr* ipHeader = (struct iphdr *)( mnl_attr_get_payload(attr[NFQA_PAYLOAD]));
    print_ip_info(ipHeader);
    uint32_t hash = 1; // create_hash(ipHeader,id);
    add_packet_sched_cb(ntohs(nfg->res_id), id, hash);
    return MNL_CB_OK;
  }


static void* thread_func(void* notUsed)
{
	/* largest possible packet payload, plus netlink data overhead: */
	size_t sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE/2);
	char* buf = malloc(sizeof_buf);
	if (!buf) {
		perror("allocate receive buffer");
		exit(EXIT_FAILURE);
	}

	unsigned int portid = mnl_socket_get_portid(nl);
	for (;;) {
		int ret = mnl_socket_recvfrom(nl, buf, sizeof_buf);
    printf("socket received data \n");
		if (ret == -1) {
			perror("mnl_socket_recvfrom");
			exit(EXIT_FAILURE);
		}

		ret = mnl_cb_run(buf, ret, 0, portid, queue_cb, NULL);
		if (ret < 0){
			perror("mnl_cb_run");
			exit(EXIT_FAILURE);
		}
	}
}

void init_nfqueue(unsigned int queue_num, void(*cb)(uint32_t, uint32_t, uint32_t))
{
	add_packet_sched_cb = cb;

	nl = mnl_socket_open(NETLINK_NETFILTER);
	if (nl == NULL) {
		perror("mnl_socket_open");
		exit(EXIT_FAILURE);
	}

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		perror("mnl_socket_bind");
		exit(EXIT_FAILURE);
	}

	/* largest possible packet payload, plus netlink data overhead: */
	size_t sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE/2);
	char* buf = malloc(sizeof_buf);
	if (!buf) {
		perror("allocate receive buffer");
		exit(EXIT_FAILURE);
	}

	/* PF_(UN)BIND is not needed with kernels 3.8 and later */
	struct nlmsghdr* nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, 0);
	nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_PF_UNBIND);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, 0);
	nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_PF_BIND);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	nlh = nfq_hdr_put(buf, NFQNL_MSG_CONFIG, queue_num);
	free(buf);

	nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

	mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
	mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}

	/* ENOBUFS is signalled to userspace when packets were lost
	 * on kernel side.  In most cases, userspace isn't interested
	 * in this information, so turn it off.
	 */
	int ret = 1;
	mnl_socket_setsockopt(nl, NETLINK_NO_ENOBUFS, &ret, sizeof(int));

	pthread_create(&thread_nfqueue, NULL, thread_func, NULL );
	//	return 0;
}

void close_nfqueue()
{
	mnl_socket_close(nl);
}

