#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h> // to be macOS compatible
#include <string.h> // for string manipulation 
#include <stdlib.h> // for string to integer conversion

#define ETH_HLEN 14  // manually define Ethernet header length

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct ip *ip_header; // changed to type IP, because type iphdr doesn't exist in this header
    // int packet_count = 0; no longer needed

    int last_octet_counts[256] = {0}; // array to hold count of each possible octet (0-255)

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

        const char *last_dot = strrchr(inet_ntoa((ip_header->ip_dst)), '.'); // get pointer to position of last '.' in IP address 
        unsigned int last_octet = atoi(last_dot + 1); // turn the string into an integer instead 

        last_octet_counts[last_octet]++; // increase count
    }

    for (int i = 0; i < 256; i++) {
        printf("Last octet %d: %d occurrences\n", i, last_octet_counts[i]);
    }

    pcap_close(handle);
    return 0;
}