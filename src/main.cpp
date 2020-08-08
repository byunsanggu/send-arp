#include <stdio.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <string.h>
#include "ethhdr.h"
#include "arphdr.h"

#define SIZE_ETHERNET 14

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void ARP_request(pcap_t* handle, char* sip, char* tip);
void ARP_reply(pcap_t* handle, char* sip, char*tip);

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        printf("%d", argc);
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    struct pcap_pkthdr* header;

    const struct libnet_ethernet_hdr* ether_packet;
    const struct libnet_ipv4_hdr* ipv4_packet;
    const u_char* packt;
    char* me_mac;

    ether_packet = (struct libnet_ethernet_hdr*)(packt);
    ipv4_packet = (struct libnet_ipv4_hdr*)(packt + SIZE_ETHERNET);


    printf("%s\n", me_mac);
/*
    EthArpPacket packet;
    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");   //you MAC
    packet.eth_.smac_ = Mac(me_mac);   //me MAC
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(me_mac);   //me MAC
    packet.arp_.sip_ = htonl(Ip(argv[2]));          //me ip
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");   //
    packet.arp_.tip_ = htonl(Ip(argv[3]));          //gateway ip

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }*/

  /*
    while(true){

        EthArpPacket packet;

        packet.eth_.dmac_ = Mac("00:00:00:00:00:00");   //you MAC
        packet.eth_.smac_ = Mac("00:00:00:00:00:00");   //me MAC
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = Mac("00:00:00:00:00:00");   //me MAC
        packet.arp_.sip_ = htonl(Ip(sip));          //gateway ip
        packet.arp_.tmac_ = Mac("00:00:00:00:00:00");   //you MAC
        packet.arp_.tip_ = htonl(Ip(tip));          //you ip

        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        

        EthArpPacket packet;
    
        packet.eth_.dmac_ = Mac("00:00:00:00:00:00");   //you MAC
        packet.eth_.smac_ = Mac("00:00:00:00:00:00");   //me MAC
        packet.eth_.type_ = htons(EthHdr::Arp);
    
        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = Mac("00:00:00:00:00:00");   //me MAC
        packet.arp_.sip_ = htonl(Ip(argv[2]));          //gateway ip
        packet.arp_.tmac_ = Mac("00:00:00:00:00:00");   //you MAC
        packet.arp_.tip_ = htonl(Ip(argv[3]));          //you ip
    
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

        
    }
*/
	pcap_close(handle);
}

/*
void ARP_request(pcap_t* handle, char* sip, char* tip){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");   //you MAC
    packet.eth_.smac_ = Mac("%x:%x:%x:%x:%x:%x",
                            ether_packet->ether_dhost[0],ether_packet->ether_dhost[1],
            ether_packet->ether_dhost[2],ether_packet->ether_dhost[3], 
            ether_packet->ether_dhost[4],ether_packet->ether_dhost[5]);   //me MAC
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac("00:00:00:00:00:00");   //me MAC
    packet.arp_.sip_ = htonl(Ip(sip));          //me ip
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");   //
    packet.arp_.tip_ = htonl(Ip(tip));          //gateway ip

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

void ARP_reply(pcap_t* handle, char* sip, char*tip){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("00:00:00:00:00:00");   //you MAC
    packet.eth_.smac_ = Mac("00:00:00:00:00:00");   //me MAC
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac("00:00:00:00:00:00");   //me MAC
    packet.arp_.sip_ = htonl(Ip(sip));          //gateway ip
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");   //you MAC
    packet.arp_.tip_ = htonl(Ip(tip));          //you ip

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}*/
