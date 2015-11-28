// Winpcap_arp.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
// 为remote***.h 头文件
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
	// 设备类型
	/*
	* struct pcap_if{
	* struct pcap_if *next;
	* char *name;
	* char *description;
	* struct pcap_addr *addresses;  设备地址结构
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

	// 获取所有网卡设备
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
	// 遍历所有获取到的网卡设备
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
			{   // 1.待解决：解析本地地址等等 2.获取本机适配器mac 地址
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

	// 选择监控的设备
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

	// 打开设备
	if ((capHandle = pcap_open_live(onedev->name,
		65536,   // 最大数据包长度
		1,  // PCAP_OPENFLAG_PROMISCUOUS，1为混杂模式
		1000,  // 超时时间，单位毫秒。注意：
		// pcap_loop 不会因为超时而返回，直到当cnt（pcap_loop第二个参数）
		// 个数据包被捕获后才返回，pcap_dispatch则因超时会返回。
		NULL   // error buf
		)) == NULL)
	{
		fprintf(stderr, "pcap_open error\n");
		pcap_freealldevs(alldevs);
		exit(-1);
	}

	// 返回链路层的类型，如以太网/wifi 。。等等不同的帧格式对应的类型
	if (pcap_datalink(capHandle) != DLT_EN10MB)
	{
		fprintf(stderr, "pcap_datalink error\n");
		pcap_freealldevs(alldevs);
		exit(-1);
	}

	// 问题：整形数据怎么和ip,掩码等等转换？
	struct bpf_program fcode;
	char packet_filter[] = "arp";   // or / and / not / src 192.168.1.x / 等等布尔表达式树

	bpf_u_int32 mask; //掩码

	if (onedev->addresses->addr->sa_family == AF_INET6)
		onedev->addresses = onedev->addresses->next;

	// 网络字节序是大端，一般电脑是小端字节序（针对long 和 short 等控制字段要注意字节序）
	if (onedev)
		mask = ((struct sockaddr_in *)(onedev->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		mask = 0xffffff;

	// 将packet_filter 字符串表达式转换成过滤结构
	// int pcap_compile(pcap_t *p, struct bpf_program *fp,char *str, int optimize, bpf_u_int32 netmask)
	if (pcap_compile(capHandle, &fcode, packet_filter, 1, mask) < 0)
	{
		fprintf(stderr, "pcap_compile error\n");
		pcap_freealldevs(alldevs);
		exit(-1);
	}
	// 设置过滤
	if (pcap_setfilter(capHandle, &fcode) < 0)
	{
		fprintf(stderr, "pcap_setfilter error\n");
		pcap_freealldevs(alldevs);
		exit(-1);
	}

	// 广播arp数据包
	BroadcastArp(capHandle, onedev);


	printf("\nListening on %s ...\n", onedev->description);

	// pcap_breakloop ， 设置标志，强制使pcap_loop , pcap_dispatch 返回，不继续循环
	// pcap_loop 不会因为超时而返回，直到当cnt个数据包被捕获后才返回，pcap_dispatch则因超时会返回。
	// 第二个参数为-1表示无限捕获
	pcap_loop(capHandle, -1, arp_handler, NULL);
	// pcap_next_ex 可用易于并发的读取帧

	//释放资源
	pcap_freealldevs(alldevs);

	return 0;
}

