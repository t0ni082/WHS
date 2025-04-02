#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <ctype.h>

/* MAC 주소 출력 함수 */
void print_mac(const u_char *mac) {
    for (int i = 0; i < 6; i++) {
        printf("%02x", mac[i]);
        if (i != 5) printf(":");
    }
}

/* 패킷을 처리하는 함수 */
void packet_processor(u_char *user, const struct pcap_pkthdr *meta, const u_char *packet) {
    struct ether_header *eth_hdr = (struct ether_header *)packet;
    struct ip *ip_hdr = (struct ip *)(packet + ETHER_HDR_LEN);
    struct tcphdr *tcp_hdr = (struct tcphdr *)(packet + ETHER_HDR_LEN + (ip_hdr->ip_hl * 4));
    
    printf("\n============= 패킷 캡처 =============\n");
    /* 이더넷 헤더 정보 출력 */
    printf("Ethernet Header:\n");
    printf("src MAC: "); print_mac(eth_hdr->ether_shost); printf("\n");
    printf("dst MAC: "); print_mac(eth_hdr->ether_dhost); printf("\n");
    
    /* IP 헤더 정보 출력 */
    printf("IP Header:\n");
    printf("src IP: %s\n", inet_ntoa(ip_hdr->ip_src));
    printf("dst IP: %s\n", inet_ntoa(ip_hdr->ip_dst));
    
    /* TCP 헤더 확인 및 출력 */
    if (ip_hdr->ip_p == IPPROTO_TCP) {
        printf("TCP Header:\n");
        printf("src port: %d\n", ntohs(tcp_hdr->th_sport));
        printf("dst port: %d\n", ntohs(tcp_hdr->th_dport));
        
        const u_char *data = (packet + ETHER_HDR_LEN + (ip_hdr->ip_hl * 4) + (tcp_hdr->th_off * 4));
        int data_length = meta->caplen - (data - packet);
        
        /* 데이터 출력(최대 100byte) */
        if (data_length > 0) {
            printf("Message:\n");
            for (int i = 0; i < data_length && i < 100; i++) {
                char c = data[i];
                printf("%c", isprint(c) ? c : '.');
            }
            if (data_length > 100) printf("...\n");
            printf("\n______________________________________");
            printf("\n(패킷 캡처 중단: Ctrl+C)\n\n");
        }
    }
    else
    printf("TCP 프로토콜 X");
}

/* 메인 함수 */
int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *processor;
    pcap_if_t *alldevs, *dev;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "디바이스 찾기 오류: %s\n", errbuf);
        return EXIT_FAILURE;
    }
    dev = alldevs;
    char *net_inter = dev->name;

    printf("사용할 네트워크 인터페이스: %s\n", net_inter);

    processor = pcap_open_live(net_inter, BUFSIZ, 1, 1000, errbuf);
    if (processor == NULL) {
        fprintf(stderr, "인터페이스 열기 오류: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return EXIT_FAILURE;
    }

    /*Ctrl+C로 패킷 캡처 중단*/
    printf("패킷 캡처 시작....\n");
    pcap_loop(processor, 0, packet_processor, NULL);
    pcap_close(processor);
    pcap_freealldevs(alldevs);
    return EXIT_SUCCESS;
}
