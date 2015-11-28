#ifndef HEADERSTRUCT_H
#define HEADERSTRUCT_H

// ip地址
typedef struct ip_address
{
	unsigned char byte1;
	unsigned char byte2;
	unsigned char byte3;
	unsigned char byte4;
}ip_address;

// ipv4首部
typedef struct ip_header
{
	unsigned char ver_ihl;  // 版本和首部长度各占4位，长度是4位数据乘以4，所以首部长度最长是60字节
	unsigned char tos;      // 区分服务
	unsigned short tlen;    // 总长度
	unsigned short identification;  // 标识
	unsigned short flags_fo;    // 标志 和 片偏移
	unsigned char ttl;          // 生存时间
	unsigned char proto;        // 协议
	unsigned short crc;         // 首部检验和
	ip_address saddr;           // 源地址
	ip_address daddr;           // 目的地址
	unsigned int op_pad;        // 可选字段 + 填充
}ip_header;

// udp首部
typedef struct udp_header
{
	unsigned short sport;
	unsigned short dport;
	unsigned short len;
	unsigned short crc;
}udp_header;

// arp数据包中的帧头
typedef struct ether_header
{   // 注意：类型字段需要转为网络字节序
	char etherdaddr[6];   // 以太网目的地址
	char ethersaddr[6];   // 以太网源地址
	unsigned short etherflametype;  // 以太网帧类型，0x0806是arp,0x0800是IP
}ether_header;

//
// arp 头部
#pragma pack(push, 1)
// c struct 编译层面字节对齐，编译器做，根据数据类型进行对齐，通过pack设置
typedef struct arp_header
{   // 注意：类型字段 和 操作码均需要转为网络字节序
	unsigned short hardtype;   // 硬件类型，如以太网为1
	unsigned short prototype;   // 协议类型,如ip 是0x0800
	unsigned char hardaddrlen;  // 硬件地址长度(6)
	unsigned char protoaddrlen; //协议地址长度，ip为4
	unsigned short operate;     // 操作字段，1为arp请求，2为arp应答
	char sendetheraddr[6]; // 发送端以太网地址
	unsigned long sendipaddr;       // 发送端ip地址
	char destetheraddr[6];    // 接收端以太网地址
	unsigned long destipaddr;       // 接收端ip地址
}arp_header/*__attribute__((aligned(1))) or __attribute__((pack)) 都是设置1字节对齐*/;
#pragma pack(pop)
//

// 值得注意的是，MSVN编译器编译结果中，两个struct并非按声明顺序在内存中存放，
// 而且，两个struct地址并不连续
typedef struct arp_packet
{
	struct ether_header etherheader;
	struct arp_header arpheader;
}arp_packet;



#endif // HEADERSTRUCT_H