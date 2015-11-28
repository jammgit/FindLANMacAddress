#ifndef HEADERSTRUCT_H
#define HEADERSTRUCT_H

// ip��ַ
typedef struct ip_address
{
	unsigned char byte1;
	unsigned char byte2;
	unsigned char byte3;
	unsigned char byte4;
}ip_address;

// ipv4�ײ�
typedef struct ip_header
{
	unsigned char ver_ihl;  // �汾���ײ����ȸ�ռ4λ��������4λ���ݳ���4�������ײ��������60�ֽ�
	unsigned char tos;      // ���ַ���
	unsigned short tlen;    // �ܳ���
	unsigned short identification;  // ��ʶ
	unsigned short flags_fo;    // ��־ �� Ƭƫ��
	unsigned char ttl;          // ����ʱ��
	unsigned char proto;        // Э��
	unsigned short crc;         // �ײ������
	ip_address saddr;           // Դ��ַ
	ip_address daddr;           // Ŀ�ĵ�ַ
	unsigned int op_pad;        // ��ѡ�ֶ� + ���
}ip_header;

// udp�ײ�
typedef struct udp_header
{
	unsigned short sport;
	unsigned short dport;
	unsigned short len;
	unsigned short crc;
}udp_header;

// arp���ݰ��е�֡ͷ
typedef struct ether_header
{   // ע�⣺�����ֶ���ҪתΪ�����ֽ���
	char etherdaddr[6];   // ��̫��Ŀ�ĵ�ַ
	char ethersaddr[6];   // ��̫��Դ��ַ
	unsigned short etherflametype;  // ��̫��֡���ͣ�0x0806��arp,0x0800��IP
}ether_header;

//
// arp ͷ��
#pragma pack(push, 1)
// c struct ��������ֽڶ��룬���������������������ͽ��ж��룬ͨ��pack����
typedef struct arp_header
{   // ע�⣺�����ֶ� �� ���������ҪתΪ�����ֽ���
	unsigned short hardtype;   // Ӳ�����ͣ�����̫��Ϊ1
	unsigned short prototype;   // Э������,��ip ��0x0800
	unsigned char hardaddrlen;  // Ӳ����ַ����(6)
	unsigned char protoaddrlen; //Э���ַ���ȣ�ipΪ4
	unsigned short operate;     // �����ֶΣ�1Ϊarp����2ΪarpӦ��
	char sendetheraddr[6]; // ���Ͷ���̫����ַ
	unsigned long sendipaddr;       // ���Ͷ�ip��ַ
	char destetheraddr[6];    // ���ն���̫����ַ
	unsigned long destipaddr;       // ���ն�ip��ַ
}arp_header/*__attribute__((aligned(1))) or __attribute__((pack)) ��������1�ֽڶ���*/;
#pragma pack(pop)
//

// ֵ��ע����ǣ�MSVN�������������У�����struct���ǰ�����˳�����ڴ��д�ţ�
// ���ң�����struct��ַ��������
typedef struct arp_packet
{
	struct ether_header etherheader;
	struct arp_header arpheader;
}arp_packet;



#endif // HEADERSTRUCT_H