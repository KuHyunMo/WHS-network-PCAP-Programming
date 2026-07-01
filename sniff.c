#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "myheader.h"   // 과제에서 준 헤더 (이 파일과 같은 폴더에 두기)

/* payload(애플리케이션 계층 데이터 = HTTP 메시지)를 사람이 읽을 수 있게 출력 */
void print_payload(const u_char *payload, int len)
{
    printf("   ----- HTTP Message (%d bytes) -----\n", len);
    for (int i = 0; i < len; i++) {
        unsigned char c = payload[i];
        // 출력 가능한 글자/줄바꿈/탭은 그대로, 나머지는 '.' 으로
        if (isprint(c) || c == '\n' || c == '\r' || c == '\t')
            putchar(c);
        else
            putchar('.');
    }
    printf("\n");
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    /* 1) IP 패킷만 처리 (0x0800 = IPv4) */
    if (ntohs(eth->ether_type) != 0x0800)
        return;

    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

    /* 2) TCP 패킷만 처리 (과제 요구사항: UDP 무시) */
    if (ip->iph_protocol != IPPROTO_TCP)
        return;

    /* IP 헤더 길이 = IHL 값 * 4
       (IHL 필드는 '4바이트 단위' 개수를 담고 있으므로 *4 해야 실제 바이트 수) */
    int ip_header_len = ip->iph_ihl * 4;

    /* TCP 헤더 시작 위치 = IP 시작 위치 + IP 헤더 길이 */
    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip_header_len);

    /* TCP 헤더 길이 = Data Offset 값 * 4
       (TH_OFF 매크로가 Data Offset 4비트를 꺼내 줌, 역시 4바이트 단위) */
    int tcp_header_len = TH_OFF(tcp) * 4;

    printf("\n==================================================\n");

    /* ===== Ethernet Header ===== */
    printf("[ Ethernet Header ]\n");
    printf("   Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
           eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
    printf("   Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
           eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

    /* ===== IP Header ===== */
    printf("[ IP Header ]\n");
    printf("   Src IP  : %s\n", inet_ntoa(ip->iph_sourceip));
    printf("   Dst IP  : %s\n", inet_ntoa(ip->iph_destip));

    /* ===== TCP Header ===== */
    printf("[ TCP Header ]\n");
    printf("   Src Port: %d\n", ntohs(tcp->tcp_sport));
    printf("   Dst Port: %d\n", ntohs(tcp->tcp_dport));

    /* ===== Payload (HTTP Message) =====
       전체 IP 길이에서 (IP 헤더 + TCP 헤더)를 빼면 순수 데이터(payload) 길이 */
    int total_len   = ntohs(ip->iph_len);   // IP 패킷 전체 길이
    int payload_len = total_len - ip_header_len - tcp_header_len;

    const u_char *payload = packet + sizeof(struct ethheader)
                            + ip_header_len + tcp_header_len;

    if (payload_len > 0)
        print_payload(payload, payload_len);
    else
        printf("[ No Message ] (payload length = 0)\n");
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp port 80";   // TCP만 + HTTP를 보기 위해 80번 포트
    bpf_u_int32 net = 0;

    // Step 1: NIC(enp0s3)에서 실시간 캡처 시작
    //  -> 본인 인터페이스 이름이 다르면 여기를 수정 (ip link 명령으로 확인)
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live error: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    // Step 2: 필터 컴파일 & 적용
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        pcap_perror(handle, "pcap_compile error:");
        return EXIT_FAILURE;
    }
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "pcap_setfilter error:");
        return EXIT_FAILURE;
    }

    // Step 3: 패킷 캡처 루프 (-1 = 무한 캡처, Ctrl+C로 종료)
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
