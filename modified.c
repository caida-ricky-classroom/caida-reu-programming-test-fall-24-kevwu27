#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h> // changed to be macOS compatible

#define ETH_HLEN 14  // manually define Ethernet header length

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct ip *ip_header; // changed to type IP, because type iphdr doesn't exist in this header
    int packet_count = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {
        ip_header = (struct ip*)(packet + ETH_HLEN); // changed to use defined Ethernet length
        printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa((ip_header->ip_dst))); // edited to get the destination address 
    }

    pcap_close(handle);
    return 0;
}