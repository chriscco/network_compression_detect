
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>
#include "config.h"
#include "cJSON.h"


#define TIMEOUT 20
#define DATAGRAM_LEN 4096
#define OPT_SIZE 20
#define BUF_SIZE 1024

struct detection_info {
    double result[2];
};

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

/**
 * Set up a raw socket, also sets the timeout for the socket
 * @return
 */
int sock_setup() {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if (sockfd < 0) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }
    int optVal = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optVal, sizeof(optVal)) < 0) {
        perror("Error setting socket options");
        exit(EXIT_FAILURE);
    }

    struct timeval timeout;
    timeout.tv_sec = TIMEOUT;
    timeout.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        perror("Error setting socket timeout");
        exit(EXIT_FAILURE);
    }
    return sockfd;
}

/**
 * Checksum function
 * @param buf
 * @param size
 * @return
 */
unsigned short checksum(const char *buf, unsigned size) {
    // CITE: https://github.com/MaxXor/raw-sockets-example/blob/master/rawsockets.c
    unsigned sum = 0, i;
    /* Accumulate checksum */
    for (i = 0; i < size - 1; i += 2) {
        unsigned short word16 = *(unsigned short *) &buf[i];
        sum += word16;
    }
    /* Handle odd-sized case */
    if (size & 1) {
        unsigned short word16 = (unsigned char) buf[i];
        sum += word16;
    }
    /* Fold to get the ones-complement result */
    while (sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16);
    /* Invert to get the negative in ones-complement arithmetic */
    return ~sum;
}


/**
 * Create UPD packets, return the sockfd for UDP
 * @param cf
 * @return return the sockfd for UDP
 */
int udp_packet_create(struct config *cf) {
    int ttl = (int) strtol(cf->udp_ttl, NULL, 10);
    int src_port_udp = (int) strtol(cf->src_port_udp, NULL, 10);
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        free(cf);
        exit(EXIT_FAILURE);
    }

    int optVal = 1;
    /* Set Don't Fragment flag.  */
    if (setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &optVal, sizeof(optVal)) < 0) {
        perror("Error setting df flag");
        free(cf);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    if (setsockopt(sockfd, SOL_SOCKET, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        perror("Error setting ttl");
        free(cf);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in udp_cli_addr;
    memset(&udp_cli_addr, 0, sizeof(udp_cli_addr));
    udp_cli_addr.sin_family = AF_INET;
    udp_cli_addr.sin_addr.s_addr = INADDR_ANY;
    udp_cli_addr.sin_port = htons(src_port_udp);
    socklen_t cli_len = sizeof(udp_cli_addr);

    if (bind(sockfd, (struct sockaddr *)&udp_cli_addr, cli_len) < 0) {
        perror("Error binding");
        free(cf);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    return sockfd;
}

/**
 * Wait for the RST packet, calculates the time taken, will be called by a thread
 * @param args
 * @return
 */
void* rst_packet_recv(void* args) {
    double* result = (double*) args;
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("Error creating socket, in rst_packet_recv\n");
        exit(EXIT_FAILURE);
    }

    char buffer[BUF_SIZE];
    struct sockaddr_in src_addr;
    socklen_t src_addr_len = sizeof(src_addr);
    src_addr.sin_addr.s_addr = INADDR_ANY;

    int optVal = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optVal, sizeof(optVal)) < 0) {
        perror("Error setsockopt in rst_packet_recv\n");
        exit(EXIT_FAILURE);
    }

    if(bind(sockfd, (struct sockaddr *)&src_addr, sizeof(src_addr)) < 0) {
        perror("Error binding socket, in rst_packet_recv\n");
        exit(EXIT_FAILURE);
    }

    struct timeval first_rst_time, second_rst_time;
    double time_interval_high, time_interval_low;
    int iter = 0;
    while (1) {
        struct iphdr *ip_header;
        struct tcphdr *tcp_header;

        bzero(buffer, BUF_SIZE);

        int n = (int) recvfrom(sockfd, buffer, BUF_SIZE, 0, (struct sockaddr *)&src_addr, &src_addr_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                printf("Timeout\n");
                break;
            } else {
                perror("Error running recvfrom()");
                exit(EXIT_FAILURE);
            }
        }

        ip_header = (struct iphdr *)buffer;
        tcp_header = (struct tcphdr *)(buffer + (ip_header->ihl * 4));

        if (tcp_header->rst == 1) {
            if (iter == 0 || iter == 2) {
                gettimeofday(&first_rst_time, NULL);
            } else if (iter == 1) {
                gettimeofday(&second_rst_time, NULL);
                time_interval_high = (double) (second_rst_time.tv_usec - first_rst_time.tv_usec) / 1000000 +
                        (double) (second_rst_time.tv_sec - first_rst_time.tv_sec);
            } else if (iter == 3) {
                gettimeofday(&second_rst_time, NULL);
                time_interval_low = (double) (second_rst_time.tv_usec - first_rst_time.tv_usec) / 1000000 +
                        (double) (second_rst_time.tv_sec - first_rst_time.tv_sec);
				break;
            }
        }
        iter++;
    }
    result[0] = time_interval_high;
    result[1] = time_interval_low;
    close(sockfd);
    return NULL;
}


/**
 * Set up SYN packets and send them
 * @param sock_raw
 * @param cf
 * @param dest_port
 */
void syn_sender(int sock_raw, struct config *cf, int dest_port) {
    // CITE: https://github.com/MaxXor/raw-sockets-example/blob/master/rawsockets.c
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(cf->server_ip);
   // char packet[BUF_SIZE];
    char* packet = calloc(BUF_SIZE, sizeof(char));

    struct iphdr* ip_h = (struct iphdr*) packet;
    struct tcphdr* tcp_h = (struct tcphdr*) (packet + sizeof(struct iphdr));
    struct pseudo_header ps_h;

    ip_h->ihl = 5;
    ip_h->version = 4;
    ip_h->tos = 0;
    ip_h->tot_len = sizeof (struct iphdr) + sizeof (struct tcphdr) + OPT_SIZE;
    ip_h->id = htonl (rand () % 65535);
    ip_h->frag_off = 0;
    ip_h->ttl = 255;
    ip_h->protocol = IPPROTO_TCP;
    ip_h->check = 0;
    ip_h->saddr = inet_addr("192.168.128.2");
    ip_h->daddr = inet_addr(cf->server_ip);

    tcp_h->source = htons(12345);
    tcp_h->dest = htons(dest_port);
    tcp_h->seq = 0;
    tcp_h->ack_seq = 0;
    tcp_h->doff = 10;
    tcp_h->fin = 0;
    tcp_h->syn = 1;
    tcp_h->rst = 0;
    tcp_h->psh = 0;
    tcp_h->ack = 0;
    tcp_h->urg = 0;
    tcp_h->check = 0;
    tcp_h->window = htons (5840);
    tcp_h->urg_ptr = 0;

    memset(&ps_h, 0, sizeof(ps_h));
    ps_h.source_address = inet_addr("192.168.128.2");
    ps_h.dest_address = inet_addr(cf->server_ip);
    ps_h.placeholder = 0;
    ps_h.protocol = IPPROTO_TCP;
    ps_h.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);

    int pseudo_size = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
    char *pseudo_packet = malloc(pseudo_size);
    memcpy(pseudo_packet, (char *) &ps_h, sizeof(struct pseudo_header));
    memcpy(pseudo_packet + sizeof(struct pseudo_header), tcp_h, sizeof(struct tcphdr) + OPT_SIZE);

    tcp_h->check = checksum(pseudo_packet, pseudo_size);
    ip_h->check = checksum(packet, ip_h->tot_len);
    int packet_size = ip_h->tot_len;

    int n = (int) sendto(sock_raw, packet, ip_h->tot_len, 0,
                         (struct sockaddr *)&dest_addr, sizeof(struct sockaddr));
    if (n < 0) {
        perror("Error sending syn packet");
        free(cf);
        exit(EXIT_FAILURE);
    }
}

/**
 * send UDP packets
 * @param dest_udp_addr
 * @param sock_udp
 * @param ifHighEntropy
 * @param cf
 */
void udp_sender(struct sockaddr_in dest_udp_addr, int sock_udp, int ifHighEntropy,
            struct config *cf) {
    int payload_size = (int) strtol(cf->udp_payload_size, NULL, 10);
    int packet_num = (int) strtol(cf->num_udp_packets, NULL, 10);
    char random[payload_size]; /* high entropy */
    get_random_byte(payload_size, random);

    char buffer[payload_size]; /* low entropy */
    memset(buffer, 0, payload_size);

    for (int i = 0; i < packet_num; i++) {
        buffer[0] = (char) ((i >> 8) & 0xFF);
        buffer[1] = (char) (i & 0xFF);
        int len;
        if (ifHighEntropy == 1) {
            len = (int) sendto(sock_udp, random, payload_size, 0, (struct sockaddr *)&dest_udp_addr,
                        sizeof(struct sockaddr));
        } else {
            len = (int) sendto(sock_udp, buffer, payload_size, 0, (struct sockaddr *) &dest_udp_addr,
                               sizeof(struct sockaddr));
        }
        if (len < 0) {
            perror("Error sending udp packet\n");
            close(sock_udp);
            exit(EXIT_FAILURE);
        }
    }
}

/**
 * main
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char *argv[]) {
    srand(time(NULL));
    struct config *cf = (struct config *) malloc(sizeof(struct config));

    FILE *file = fopen("myconfig.json", "r");
    cJSON* root = read_file_config(file);
    get_configuration(cf, root);

    printf("Setting up raw socket...\n");

    int sock_raw = sock_setup();
    int dest_port_tcp_head = (int) strtol(cf->dst_port_tcp_head, NULL, 10);
    struct sockaddr_in head_dst_addr;
    head_dst_addr.sin_family = AF_INET;
    head_dst_addr.sin_port = htons(dest_port_tcp_head);
    head_dst_addr.sin_addr.s_addr = inet_addr(cf->server_ip);

    struct sockaddr_in tail_dst_addr;
    int dest_port_tcp_tail = (int) strtol(cf->dst_port_tcp_tail, NULL, 10);
    tail_dst_addr.sin_family = AF_INET;
    tail_dst_addr.sin_port = htons(dest_port_tcp_tail);
    tail_dst_addr.sin_addr.s_addr = inet_addr(cf->server_ip);

    struct sockaddr_in src_addr;
    src_addr.sin_family = AF_INET;
    src_addr.sin_addr.s_addr = inet_addr("192.168.128.2");


    int sock_udp = udp_packet_create(cf);

    struct sockaddr_in dst_udp_addr;
    int dest_port_udp = (int) strtol(cf->dst_port_udp, NULL, 10);
    dst_udp_addr.sin_family = AF_INET;
    dst_udp_addr.sin_port = htons(dest_port_udp);
    dst_udp_addr.sin_addr.s_addr = inet_addr(cf->server_ip);

    double time_diff[2];
    pthread_t thread;
    double result[2];

    int n = pthread_create(&thread, NULL, rst_packet_recv, (void*)&result);
    if (n < 0) {
        perror("Error creating thread, rst_packet_recv\n");
        free(cf);
        close(sock_raw);
        close(sock_udp);
        exit(EXIT_FAILURE);
    }

    printf("sending head syn...\n");
    syn_sender(sock_raw, cf, dest_port_tcp_head);
    printf("finished sending head syn\nSending low entropy udp packets...\n");
    udp_sender(dst_udp_addr, sock_udp, 0, cf);
    printf("finished sending low entropy udp packets\nSending tail syn...\n");
    syn_sender(sock_raw, cf, dest_port_tcp_tail);

    int inter_time = (int) strtol(cf->inter_measure_time, NULL, 10);
    sleep(inter_time);

    printf("Sending head syn...\n");
    syn_sender(sock_raw, cf, dest_port_tcp_head);
    printf("Sending high entropy udp packets...\n");
    udp_sender(dst_udp_addr, sock_udp, 1, cf);
    printf("finished sending high entropy udp packets\nSending tail syn...\n");
    syn_sender(sock_raw, cf, dest_port_tcp_tail);
    
    pthread_join(thread, NULL);
    
    printf("Time interval high entropy: %f\n", result[0]);
    printf("Time interval low entropy: %f\n", result[1]);
    if (result[0] - result[1] > 100) {
        printf("Compression detected\n");
    } else {
        printf("No compression detected\n");
    }
    
    free(cf);
    close(sock_raw);
    close(sock_udp);
    return 0;

}
