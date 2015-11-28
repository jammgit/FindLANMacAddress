#ifndef TRANSFUNC_H
#define TRANSFUNC_H

// 为remote***.h 头文件
#ifndef HAVE_REMOTE
#define HAVE_REMOTE
#endif
#include "pcap.h"
#include "remote-ext.h"
#include "Packet32.h"
#include "datastruct.h"

int GetSelfMac(pcap_t *adhandle, const char *ip_addr, char *ip_mac);
void BroadcastArp(pcap_t *handle, pcap_if_t *dev);
int GetMacAddress(char* source, char* mac_buf);
void arp_handler(unsigned char*param, const struct pcap_pkthdr *header,
	const unsigned char *pkt_data);
char *ip6toa(struct sockaddr *sockaddr, char *address, int addrlen);

#endif