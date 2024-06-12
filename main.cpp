#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include "ethhdr.h"
#include "tcphdr.h"
#include "iphdr.h"

#define MSG "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n\r\n"

void usage() {
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

typedef struct s_info {
	Mac	mac;
	Ip	ip;
} t_info;

t_info MyInfo;

#pragma pack(push, 1)
typedef struct EthIpTcpHdr final
{
	EthHdr	ethHdr_;
	IpHdr	ipHdr_;
	TcpHdr	tcpHdr_;
}	EthIpTcpHdr;
#pragma pack(pop)


typedef struct _PseudoHdr{
	uint32_t srcAddr;
    uint32_t dstAddr;
    uint8_t reserved;
    uint8_t proto;
    uint16_t tcpLen;
}	PseudoHdr;


int	getMyInfo(t_info *MyInfo, char *dev){
	struct ifreq ifr;
   	int fd;

	fd = socket(PF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev);

    if (!ioctl(fd, SIOCGIFHWADDR, &ifr)){
		MyInfo->mac = Mac((uint8_t *)ifr.ifr_hwaddr.sa_data);
	}
	else return 1;

	if (!ioctl(fd, SIOCGIFADDR, &ifr)){
		MyInfo->ip = Ip(ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr));
	}
	else return 1;

	printf("My mac addr: [%s]\n", std::string(MyInfo->mac).data());
	printf("My ip addr: [%s]\n", std::string(MyInfo->ip).data());
	close(fd);
	return 0;
}

uint16_t CheckSum(uint16_t *buffer, int size){
    uint16_t cksum = 0;

    while(size > 1){
        cksum += *buffer++;
        size -= 2;
    }

    if(size > 0)
        cksum += *(uint8_t*)buffer;

    while (cksum >> 16) {
        cksum = (cksum & 0xFFFF) + (cksum >> 16);
    }

    return (uint16_t)(~cksum);
}


int main(int argc, char* argv[]){
	if(argc != 3){
		usage();
		return 1;
	}
	char* dev = argv[1];
	char* pattern = argv[2];
	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	getMyInfo(&MyInfo, dev);

	while(true){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

		EthIpTcpHdr	*ethIpTcpHdr = (EthIpTcpHdr *)packet;

		// eth header
        if (ethIpTcpHdr->ethHdr_.type() != EthHdr::Ip4) continue; // ipv4

		// ip header
        uint32_t iphdr_len = ethIpTcpHdr->ipHdr_.ip_len * 4;
        uint32_t ippkt_len = ntohs(ethIpTcpHdr->ipHdr_.total_len);
        if (ethIpTcpHdr->ipHdr_.proto != 6) continue; // tcp

		// tcp header
        uint32_t tcphdr_len = ethIpTcpHdr->tcpHdr_.th_off * 4;
        uint32_t tcpdata_len = ippkt_len - iphdr_len - tcphdr_len;
        if (tcpdata_len == 0) continue; // no data

		char *data = (char*)(packet + sizeof(EthHdr) + iphdr_len + tcphdr_len);
		if(strstr(data, pattern) == NULL){
			continue;
		}


		// Forward Packet
		EthIpTcpHdr* forward_packet;
		uint32_t fwd_len = sizeof(EthIpTcpHdr); // no data
		memcpy(&forward_packet, packet, sizeof(EthIpTcpHdr));

		forward_packet->ethHdr_.smac_ = MyInfo.mac;

		forward_packet->ipHdr_.total_len = htons(iphdr_len + tcphdr_len);
		forward_packet->ipHdr_.check = 0;
		forward_packet->ipHdr_.check = CheckSum((uint16_t*)&forward_packet->ipHdr_, sizeof(IpHdr));
		
		forward_packet->tcpHdr_.seqnum = htonl(ntohl(ethIpTcpHdr->tcpHdr_.seqnum) + tcpdata_len);
		forward_packet->tcpHdr_.flags = 0b00010100; // RST | ACK flag
		forward_packet->tcpHdr_.th_off = (sizeof(TcpHdr) / 4);
		forward_packet->tcpHdr_.check = 0;

		PseudoHdr* pseudoHdr;
		memset(pseudoHdr, 0, sizeof(PseudoHdr));
		pseudoHdr->srcAddr = ethIpTcpHdr->ipHdr_.sip_;
		pseudoHdr->dstAddr = ethIpTcpHdr->ipHdr_.dip_;
		pseudoHdr->proto = ethIpTcpHdr->ipHdr_.proto;
		pseudoHdr->tcpLen = htons(sizeof(TcpHdr));

		uint32_t sum = CheckSum((uint16_t*)&forward_packet->tcpHdr_, sizeof(TcpHdr)) + CheckSum((uint16_t*)&pseudoHdr, sizeof(PseudoHdr));
		forward_packet->tcpHdr_.check = (sum & 0xffff) + (sum >> 16);

		if (pcap_sendpacket(handle, reinterpret_cast<const u_char*>(forward_packet), fwd_len)) {
			printf("pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }


		// Backward Packet
		struct {
			EthIpTcpHdr backward_Hdr;
			char msg[sizeof(MSG)];
		} p;

		uint32_t bck_len = sizeof(EthIpTcpHdr) + sizeof(MSG);
		memcpy(&p.backward_Hdr, packet, sizeof(EthIpTcpHdr));
		memcpy(&p.msg, MSG, sizeof(MSG));

		p.backward_Hdr.ethHdr_.smac_ = MyInfo.mac;
		p.backward_Hdr.ethHdr_.dmac_ = ethIpTcpHdr->ethHdr_.smac_;

		p.backward_Hdr.ipHdr_.total_len = htons(iphdr_len + tcphdr_len + sizeof(MSG));
		p.backward_Hdr.ipHdr_.ttl = 128;
		p.backward_Hdr.ipHdr_.sip_ = ethIpTcpHdr->ipHdr_.dip_;
		p.backward_Hdr.ipHdr_.dip_ = ethIpTcpHdr->ipHdr_.sip_;
		p.backward_Hdr.ipHdr_.check = 0;
		p.backward_Hdr.ipHdr_.check = CheckSum((uint16_t*)&p.backward_Hdr.ipHdr_, sizeof(IpHdr));
		
		p.backward_Hdr.tcpHdr_.sport = ethIpTcpHdr->tcpHdr_.dport;
		p.backward_Hdr.tcpHdr_.dport = ethIpTcpHdr->tcpHdr_.sport;
		p.backward_Hdr.tcpHdr_.acknum = htonl(ntohl(ethIpTcpHdr->tcpHdr_.seqnum) + tcpdata_len);
		p.backward_Hdr.tcpHdr_.seqnum = ethIpTcpHdr->tcpHdr_.acknum;
		p.backward_Hdr.tcpHdr_.flags = 0b00010001; // ACK | FIN flag
		p.backward_Hdr.tcpHdr_.th_off = (sizeof(TcpHdr) / 4);
		p.backward_Hdr.tcpHdr_.check = 0;

		memset(pseudoHdr, 0, sizeof(PseudoHdr));
		pseudoHdr->srcAddr = ethIpTcpHdr->ipHdr_.dip_;
		pseudoHdr->dstAddr = ethIpTcpHdr->ipHdr_.sip_;
		pseudoHdr->proto = ethIpTcpHdr->ipHdr_.proto;
		pseudoHdr->tcpLen = htons(sizeof(TcpHdr));

		sum = CheckSum((uint16_t*)&p.backward_Hdr.tcpHdr_, sizeof(TcpHdr)) + CheckSum((uint16_t*)&pseudoHdr, sizeof(PseudoHdr));
		p.backward_Hdr.tcpHdr_.check = (sum & 0xffff) + (sum >> 16);

		int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
		const int on = 1;
		setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));


		struct sockaddr_in sockaddr;
		sockaddr.sin_family = AF_INET;
		sockaddr.sin_port = ethIpTcpHdr->tcpHdr_.sport;
		sockaddr.sin_addr.s_addr = ethIpTcpHdr->ipHdr_.sip_;
		sendto(sockfd, &p.backward_Hdr.ipHdr_, sizeof(IpHdr) + sizeof(TcpHdr) + sizeof(MSG), 0, (struct sockaddr *)(&sockaddr), sizeof(sockaddr));
		close(sockfd);
 



	}

}