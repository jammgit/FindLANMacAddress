// Winpcap_arp.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
// Ϊremote***.h ͷ�ļ�
#ifndef HAVE_REMOTE
#define HAVE_REMOTE
#endif

#include "pcap.h"
#include "remote-ext.h"
#include <winsock.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "datastruct.h"
#include "transfunc.h"

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "Ws2_32.lib")

int _tmain(int argc, _TCHAR* argv[])
{
	// �豸����
	/*
	* struct pcap_if{
	* struct pcap_if *next;
	* char *name;
	* char *description;
	* struct pcap_addr *addresses;  �豸��ַ�ṹ
	* bpf_u_int32 flags;
	* };
	*/
	pcap_if_t *alldevs = NULL, *onedev = NULL;
	/*
	* struct pcap_addr{
	* struct pcap_addr *next;
	* struct sockaddr *addr;
	* ...              netmask, broadaddr, dstaddr;
	* };
	*/
	pcap_addr *devsaddr = NULL;
	char ip6str[128];
	char error[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE] = "rpcap://";
	int index;

	// ��ȡ���������豸
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, error) < 0)
	{
		fprintf(stderr, "pcap_findalldevs error.\n");
		exit(-1);
	}
	if (alldevs == NULL)
	{
		printf("No device found\n");
		return 0;
	}
	// �������л�ȡ���������豸
	for (onedev = alldevs, index = 1; onedev != NULL; onedev = onedev->next, ++index)
	{
		printf("(%d)%s", index, onedev->name);
		if (onedev->description)
			printf("description: %s\n", onedev->description);
		else
			printf("No description available\n");
		if (onedev->flags == PCAP_IF_LOOPBACK) 
			printf("Lookback device.\n");
		devsaddr = onedev->addresses;
		
		for (; devsaddr; devsaddr = devsaddr->next)
		{
			switch (devsaddr->addr->sa_family)
			{   // 1.��������������ص�ַ�ȵ� 2.��ȡ����������mac ��ַ
			case AF_INET:
				printf("\tAddress family name : AF_INET\n");
				if (devsaddr->addr)
					printf("\tAddress : %s\n", inet_ntoa(
					((struct sockaddr_in *)(devsaddr->addr))->sin_addr));
				if (devsaddr->netmask)
					printf("\tAddress netmask : %s\n", inet_ntoa(
					((struct sockaddr_in *)(devsaddr->netmask))->sin_addr));
				if (devsaddr->broadaddr)
					printf("\tAddress broadcast : %s\n", inet_ntoa(
					((struct sockaddr_in *)(devsaddr->broadaddr))->sin_addr));
				if (devsaddr->dstaddr)
					printf("\tAddress destination : %s\n", inet_ntoa(
					((struct sockaddr_in *)(devsaddr->dstaddr))->sin_addr));
				break;
			case AF_INET6:
				printf("\tAddress family name : AF_INET6\n");
				if (devsaddr->addr)
				{
					//                    memset(ip6str, 0, sizeof(ip6str));
					//                    ip6toa(devsaddr->addr, ip6str, sizeof(ip6str));
					//                    printf("\tAddress : %s\n", ip6str);
				}
				break;
			default:
				printf("\tAddress family no found\n");
				break;

			}
		}
		printf(("-----------------------------------sperator-------------------------------------\n"));
	}

	// ѡ���ص��豸
reenter:
	printf("Enter which interface[1,%d] you want to scrap:", index - 1);
	int which, iindex;
	scanf("%d", &which);
	if (which < 1 || which > index - 1)
	{
		printf("enter error\n");
		goto reenter;
	}
	for (onedev = alldevs, iindex = 1; iindex <= index - 1; ++iindex, onedev = onedev->next)
	{
		if (iindex == which)
		{
			break;
		}
	}
	if (iindex == index)
	{
		fprintf(stderr, "Find device error\n");
		exit(-1);
	}
	pcap_t *capHandle = NULL;

	// ���豸
	if ((capHandle = pcap_open_live(onedev->name,
		65536,   // ������ݰ�����
		1,  // PCAP_OPENFLAG_PROMISCUOUS��1Ϊ����ģʽ
		1000,  // ��ʱʱ�䣬��λ���롣ע�⣺
		// pcap_loop ������Ϊ��ʱ�����أ�ֱ����cnt��pcap_loop�ڶ���������
		// �����ݰ��������ŷ��أ�pcap_dispatch����ʱ�᷵�ء�
		NULL   // error buf
		)) == NULL)
	{
		fprintf(stderr, "pcap_open error\n");
		pcap_freealldevs(alldevs);
		exit(-1);
	}

	// ������·������ͣ�����̫��/wifi �����ȵȲ�ͬ��֡��ʽ��Ӧ������
	if (pcap_datalink(capHandle) != DLT_EN10MB)
	{
		fprintf(stderr, "pcap_datalink error\n");
		pcap_freealldevs(alldevs);
		exit(-1);
	}

	// ���⣺����������ô��ip,����ȵ�ת����
	struct bpf_program fcode;
	char packet_filter[] = "arp";   // or / and / not / src 192.168.1.x / �ȵȲ������ʽ��

	bpf_u_int32 mask; //����

	if (onedev->addresses->addr->sa_family == AF_INET6)
		onedev->addresses = onedev->addresses->next;

	// �����ֽ����Ǵ�ˣ�һ�������С���ֽ������long �� short �ȿ����ֶ�Ҫע���ֽ���
	if (onedev)
		mask = ((struct sockaddr_in *)(onedev->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		mask = 0xffffff;

	// ��packet_filter �ַ������ʽת���ɹ��˽ṹ
	// int pcap_compile(pcap_t *p, struct bpf_program *fp,char *str, int optimize, bpf_u_int32 netmask)
	if (pcap_compile(capHandle, &fcode, packet_filter, 1, mask) < 0)
	{
		fprintf(stderr, "pcap_compile error\n");
		pcap_freealldevs(alldevs);
		exit(-1);
	}
	// ���ù���
	if (pcap_setfilter(capHandle, &fcode) < 0)
	{
		fprintf(stderr, "pcap_setfilter error\n");
		pcap_freealldevs(alldevs);
		exit(-1);
	}

	// �㲥arp���ݰ�
	BroadcastArp(capHandle, onedev);


	printf("\nListening on %s ...\n", onedev->description);

	// pcap_breakloop �� ���ñ�־��ǿ��ʹpcap_loop , pcap_dispatch ���أ�������ѭ��
	// pcap_loop ������Ϊ��ʱ�����أ�ֱ����cnt�����ݰ��������ŷ��أ�pcap_dispatch����ʱ�᷵�ء�
	// �ڶ�������Ϊ-1��ʾ���޲���
	pcap_loop(capHandle, -1, arp_handler, NULL);
	// pcap_next_ex �������ڲ����Ķ�ȡ֡

	//�ͷ���Դ
	pcap_freealldevs(alldevs);

	return 0;
}

