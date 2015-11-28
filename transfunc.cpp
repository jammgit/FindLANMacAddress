#include "stdafx.h"

#include "transfunc.h"


void arp_handler(unsigned char*param,                   // ��Ӧpcap_loop / pcap_dispatch �Ĳ���
	const struct pcap_pkthdr *header,      //winpcap ���ɵ�һ��ͷ
	const unsigned char *pkt_data)         // ���ݰ�
{   // �������������Ӧ��arp ���ݰ�
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
	// ע�⣬����ῴ�����mac Ϊȫ0����Ϊ����BroadArp������㲥��һ��arp����
	// ������һ��ԴmacΪȫ���arp�����������յ���

	// ������ȷ�ˣ�����arpϵͳ�Զ����İ��������Ҵ����ģ�����ץȡ����
	if (arp.etherheader.etherflametype == htons(0x0806))
		printf("ip: %d.%d.%d.%d -> MAC:%.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n",
		ipaddr->byte1, ipaddr->byte2, ipaddr->byte3, ipaddr->byte4,
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

}
// �ʣ�Ϊʲô��Ҫ�����ֽ���
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

	//    inet_addr �õ��������������ĵ�ַ˳���෴������˵�����е�Ip�ǰ��շ���8bitΪһ�Σ��洢��
	//    ��192.168.1.107,���������Ĵ洢��ʽΪ (((107*256 + 1)*256)+168)*256 + 192
	broadip = ((struct sockaddr_in *)(dev->addresses->broadaddr))->sin_addr.S_un.S_addr;
	//    printf("1.%u\n", broadip);


	//��ʼ����̫��ͷ��
	memset(arp.etherheader.etherdaddr, 0xff, 6); // �㲥MAC��ַ

	strncpy(arp.etherheader.ethersaddr, mac, 6);
	arp.etherheader.etherflametype = htons(0x0806); // 0x8060��arp
	//��ʼ��arpͷ�� ����ʱ��arp_header���mac��ַ����������ֵ������Ӱ��
	arp.arpheader.hardtype = htons(1);
	arp.arpheader.prototype = htons(0x0800); // 0x0800��ip
	arp.arpheader.hardaddrlen = 6;
	arp.arpheader.protoaddrlen = 4;
	arp.arpheader.operate = htons(1); // 1��arp����,2��arpӦ��
	strncpy(arp.arpheader.sendetheraddr, arp.etherheader.ethersaddr, 6);
	// ����ֵ
	memset(arp.arpheader.destetheraddr, 0xff, 6);
	arp.arpheader.sendipaddr = ((struct sockaddr_in *)(dev->addresses->addr))->sin_addr.S_un.S_addr;
	// ����broadip ��255.255.255.255��ȫ���㲥IP���ģ�����wireshark������ʾ��˭��255.255.255.255 ��������������õ�sendipaddr
	arp.arpheader.destipaddr = broadip;
	// ����arp���ݰ�

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
	unsigned char sendbuf[42]; //arp���ṹ��С
	int i = -1;
	int res;
	ether_header eh; //��̫��֡ͷ
	arp_header ah;  //ARP֡ͷ
	struct pcap_pkthdr * pkt_header;
	const u_char * pkt_data;
	//���ѿ����ڴ�ռ� eh.dest_mac_add ���� 6���ֽڵ�ֵ��Ϊֵ 0xff��
	memset(eh.etherdaddr, 0xff, 6); //Ŀ�ĵ�ַΪȫΪ�㲥��ַ
	// ����̫��Դ��ַΪ0����arp, ���ն��������յ��޶˵�arp���ͷ���һ�������Լ�mac��ַ��arp
	// �����޶ˡ���ip��Ӧ��������
	memset(eh.ethersaddr, 0x00, 6);

	// ����Դmac��ַ������ʽ��arp����
	// arpheader�����̫����ַû��
	memset(ah.destetheraddr, 0xff, 6);
	memset(ah.sendetheraddr, 0x00, 6);
	//htons��һ���޷��Ŷ����͵�������ֵת��Ϊ�����ֽ�˳��
	eh.etherflametype = htons(0x0806);
	ah.hardtype = htons(0x0001);
	ah.prototype = htons(0x0800);
	ah.hardaddrlen = 6;
	ah.protoaddrlen = 4;
	ah.sendipaddr = inet_addr(ip_addr); //����������ip
	ah.operate = htons(0x0001);
	// �����192.168.223.255, ������������ַ��˭�ģ���Ϊ���Ǹ��㲥��ַ
	// �Ƿ�ʲô���󣿣�vmnet8 �Ĳ��ԣ���xxx.1����gratuitous���޶˵ģ���������xxx.1
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
	//��interface�����߼�¼�ļ���ȡһ������
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
			// Ϊʲô������ܶ�ffff
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


// ���������������ֻ���ҵ���ʱ���Ǵ��������ĺ�������
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
