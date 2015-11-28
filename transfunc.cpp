#include "stdafx.h"

#include "transfunc.h"


void arp_handler(unsigned char*param,                   // 对应pcap_loop / pcap_dispatch 的参数
	const struct pcap_pkthdr *header,      //winpcap 生成的一个头
	const unsigned char *pkt_data)         // 数据包
{   // 代解决：解析响应得arp 数据包
	struct arp_packet arp;
	memcpy(&arp.etherheader, pkt_data, 14);
	memcpy(&arp.arpheader, pkt_data + 14, 28);
	//struct ip_address *ipaddr = (struct ip_address *)(static_cast<void *>(&(arp->arpheader.sendipaddr)));

	unsigned char mac[6];
	for (int index = 0; index < 6; ++index)
	{
		mac[index] = arp.etherheader.ethersaddr[index];
	}
	unsigned long sendip = arp.arpheader.sendipaddr;
	struct ip_address *ipaddr = static_cast<struct ip_address *>((void *)&sendip);
	// 注意，这里会看到输出mac 为全0，因为我在BroadArp函数里广播了一个arp包，
	// 曾发送一个源mac为全零的arp，估计现在收到了

	// 后来正确了，那是arp系统自动发的包（不是我触发的），我抓取到了
	if (arp.etherheader.etherflametype == htons(0x0806))
		printf("ip: %d.%d.%d.%d -> MAC:%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n",
		ipaddr->byte1, ipaddr->byte2, ipaddr->byte3, ipaddr->byte4,
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

}
// 问：为什么需要网络字节序？
void BroadcastArp(pcap_t *handle, pcap_if_t *dev)
{
	struct arp_packet arp;
	char mac[6];
	if (dev->addresses->addr->sa_family == AF_INET6)
		dev->addresses = dev->addresses->next;


	if (
		GetSelfMac(handle,
		inet_ntoa(((struct sockaddr_in *)(dev->addresses->addr))->sin_addr),
		mac)
		< 0)
	{
		fprintf(stderr, "GetSelfMac error\n");
		exit(-1);
	}

	bpf_u_int32 broadip = 0;

	//    inet_addr 得到的正数解析出的地址顺序相反，就是说传输中的Ip是按照反序（8bit为一段）存储的
	//    如192.168.1.107,则在整数的存储方式为 (((107*256 + 1)*256)+168)*256 + 192
	broadip = ((struct sockaddr_in *)(dev->addresses->broadaddr))->sin_addr.S_un.S_addr;
	//    printf("1.%u\n", broadip);


	//初始化以太网头部
	memset(arp.etherheader.etherdaddr, 0xff, 6); // 广播MAC地址

	strncpy(arp.etherheader.ethersaddr, mac, 6);
	arp.etherheader.etherflametype = htons(0x0806); // 0x8060是arp
	//初始化arp头， 请求时，arp_header里的mac地址可以是任意值，不受影响
	arp.arpheader.hardtype = htons(1);
	arp.arpheader.prototype = htons(0x0800); // 0x0800是ip
	arp.arpheader.hardaddrlen = 6;
	arp.arpheader.protoaddrlen = 4;
	arp.arpheader.operate = htons(1); // 1是arp请求,2是arp应答
	strncpy(arp.arpheader.sendetheraddr, arp.etherheader.ethersaddr, 6);
	// 任意值
	memset(arp.arpheader.destetheraddr, 0xff, 6);
	arp.arpheader.sendipaddr = ((struct sockaddr_in *)(dev->addresses->addr))->sin_addr.S_un.S_addr;
	// 这里broadip 是255.255.255.255（全网广播IP来的），用wireshark发现提示，谁是255.255.255.255 ，请告诉上面设置的sendipaddr
	arp.arpheader.destipaddr = broadip;
	// 发送arp数据包

	unsigned char *buf = (unsigned char *)malloc(42);
	memset(buf, 0, 42);
	memcpy(buf, &(arp.etherheader), sizeof(arp.etherheader));
	memcpy(buf + sizeof(arp.etherheader), &(arp.arpheader), sizeof(arp.arpheader));
	// fatal bad memory block!!!
	if (pcap_sendpacket(handle, buf, 42) < 0)
	{
		fprintf(stderr, "pacap_sendpacket error\n");
		exit(-1);
	}
	free(buf);
}
int GetSelfMac(pcap_t *adhandle, const char *ip_addr, char *ip_mac)
{
	// 
	unsigned char sendbuf[42]; //arp包结构大小
	int i = -1;
	int res;
	ether_header eh; //以太网帧头
	arp_header ah;  //ARP帧头
	struct pcap_pkthdr * pkt_header;
	const u_char * pkt_data;
	//将已开辟内存空间 eh.dest_mac_add 的首 6个字节的值设为值 0xff。
	memset(eh.etherdaddr, 0xff, 6); //目的地址为全为广播地址
	// 以以太网源地址为0发送arp, 接收端网卡接收到无端的arp，就发送一个包含自己mac地址的arp
	// 到”无端“的ip对应的主机，
	memset(eh.ethersaddr, 0x00, 6);

	// 当有源mac地址则是正式的arp请求
	// arpheader里的以太网地址没用
	memset(ah.destetheraddr, 0xff, 6);
	memset(ah.sendetheraddr, 0x00, 6);
	//htons将一个无符号短整型的主机数值转换为网络字节顺序
	eh.etherflametype = htons(0x0806);
	ah.hardtype = htons(0x0001);
	ah.prototype = htons(0x0800);
	ah.hardaddrlen = 6;
	ah.protoaddrlen = 4;
	ah.sendipaddr = inet_addr(ip_addr); //随便设的请求方ip
	ah.operate = htons(0x0001);
	// 如果是192.168.223.255, 则是提高这个地址是谁的，因为这是个广播地址
	// 是否什么错误？（vmnet8 的测试），xxx.1则是gratuitous（无端的）请求，来自xxx.1
	ah.destipaddr = inet_addr(ip_addr);
	printf("sizeof(eh) = %d \t sizeof(ah) = %d\n", sizeof(eh), sizeof(ah));
	memset(sendbuf, sizeof(sendbuf), 0);
	memcpy(sendbuf, &eh, sizeof(eh));
	memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
	///	printf("%s", sendbuf);
	if (pcap_sendpacket(adhandle, sendbuf, 42) == 0) {
		printf("\nPacketSend succeed\n");
	}
	else {
		printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
		return 0;
	}
	//从interface或离线记录文件获取一个报文
	//pcap_next_ex(pcap_t* p,struct pcap_pkthdr** pkt_header,const u_char** pkt_data)
	int count = 0;
	while ((res = pcap_next_ex(adhandle, &pkt_header, &pkt_data)) >= 0) {
		if (*(unsigned short *)(pkt_data + 12) == htons(0x0806)
			&& *(unsigned short*)(pkt_data + 20) == htons(0x0002)
			&& *(unsigned long*)(pkt_data + 28)
			== inet_addr(ip_addr)) {
			for (i = 0; i < 6; i++) {
				ip_mac[i] = *(unsigned char *)(pkt_data + 22 + i);
			}
			// 为什么会输出很多ffff
			printf("MAC:%2.2x.%2.2x.%2.2x.%2.2x.%2.2x.%2.2x\t", ip_mac[0], ip_mac[1], ip_mac[2], ip_mac[3], ip_mac[4],
				ip_mac[5]);
			printf("Get mac success !\n");
			break;
		}
	}
	if (i == 6) {
		return 1;
	}
	else {
		return -1;
	}
}


// 网上有这个方法，只是我调用时总是打开适配器的函数出错
int GetMacAddress(char* source, char* mac_buf)
{
	LPADAPTER lpAdapter;
	PPACKET_OID_DATA  OidData;
	BOOLEAN status;

	lpAdapter = PacketOpenAdapter(source);

	if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE))
	{
		printf("error : %d\n", GetLastError());
		return -1;
	}

	OidData = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
	if (OidData == NULL)
	{
		return 0;
	}

	OidData->Oid = 0x01010102;//OID_802_3_CURRENT_ADDRESS;
	OidData->Length = 6;
	ZeroMemory(OidData->Data, 6);

	status = PacketRequest(lpAdapter, FALSE, OidData);
	if (!status)
	{
		return -1;
	}

	memcpy((void *)mac_buf, (void *)OidData->Data, 6);

	printf("The MAC address of the adapter is %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
		(PCHAR)(OidData->Data)[0],
		(PCHAR)(OidData->Data)[1],
		(PCHAR)(OidData->Data)[2],
		(PCHAR)(OidData->Data)[3],
		(PCHAR)(OidData->Data)[4],
		(PCHAR)(OidData->Data)[5]);

	free(OidData);
	PacketCloseAdapter((LPADAPTER)source);

	return 1;
}

char *ip6toa(struct sockaddr *sockaddr, char *address, int addrlen)
{
	socklen_t sockaddrlen;
#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif
	if (getnameinfo(sockaddr, sockaddrlen, address, addrlen, NULL,
		0, NI_NUMERICHOST) != 0)
		address[0] = '\0';
	return address;
}
