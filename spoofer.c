#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    int sockfd;
    struct sockaddr_in dest_addr;
    char packet[4096];
    int packet_len;
    int on = 1;

    // Create a raw socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("socket() failed");
        return -1;
    }

    // Allow socket to send packets with fabricated IP header
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt() failed");
        return -1;
    }

    // Set up the IP header
    struct iphdr *ip_header = (struct iphdr *) packet;
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = htons(40);
    ip_header->id = htons(rand());
    ip_header->frag_off = 0;
    ip_header->ttl = 255;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check = 0;
    ip_header->saddr = inet_addr("192.168.1.1");
    ip_header->daddr = inet_addr("192.168.1.2");

    // Set up the TCP header
    struct tcphdr *tcp_header = (struct tcphdr *) (packet + sizeof(struct iphdr));
    tcp_header->source = htons(1234);
    tcp_header->dest = htons(5678);
    tcp_header->seq = htonl(rand());
    tcp_header->ack_seq = 0;
    tcp_header->doff = 5;
    tcp_header->fin = 0;
    tcp_header->syn

}