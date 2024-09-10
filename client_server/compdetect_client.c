#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "config.h"
#include "cJSON.h"

#define BUF_SIZE 1024

/**
 * Sends the configuration data to the server
 * @param cf configuration struct
 * @param root JSON object
 * @param file configuration file
 * @param sockfd socket file descriptor
 */
void pre_probe_sender(struct config* cf, cJSON* root, FILE* file, int sockfd) {
    struct sockaddr_in serv_addr;
    int port = (int) strtol(cf->pre_probe_port, NULL, 10);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(cf->server_ip);
    serv_addr.sin_port = htons(port);

    int optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("Error setting socket options");
        exit(EXIT_FAILURE);
    }

    int rc = connect(sockfd, (const struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if(rc == -1) {
        perror("failed to connect");
        exit(EXIT_FAILURE);
    }

    char* buffer = cJSON_PrintUnformatted(root);
    if (send(sockfd, buffer, strlen(buffer), 0) < 0) {
        perror("failed to send config");
        exit(EXIT_FAILURE);
    }
    cJSON_Delete(root);
    close(sockfd);
}

/**
 * Sends the UDP packets to the server
 * @param cf configuration struct
 * @param sockfd socket file descriptor
 */
void probing_udp_sender(struct config* cf, int sockfd) {
    int src_port = (int) strtol(cf->src_port_udp, NULL, 10);
    struct sockaddr_in udp_cli_addr;
    udp_cli_addr.sin_family = AF_INET;
    udp_cli_addr.sin_addr.s_addr = inet_addr("192.168.128.2");
    udp_cli_addr.sin_port = htons(src_port);

    int df_flag = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &df_flag, sizeof(df_flag)) < 0) {
        perror("failed to set df flag val");
        exit(1);
    }
    if (bind(sockfd, (struct sockaddr *)&udp_cli_addr, sizeof(udp_cli_addr)) < 0) {
        perror("failed to bind, probing udp sender");
        exit(1);
    }
    struct sockaddr_in server_addr;
    int dst_port = (int) strtol(cf->dst_port_udp, NULL, 10);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(cf->server_ip);
    server_addr.sin_port = htons(dst_port);

    int payload_size = (int) strtol(cf->udp_payload_size, NULL, 10);
    int num_packets = (int) strtol(cf->num_udp_packets, NULL, 10);
    int interval_time = (int) strtol(cf->inter_measure_time, NULL, 10);
    char buffer[payload_size];
    memset(&buffer, 0, payload_size);

    printf("Sending low entropy packets...\n");
    for (int i = 0; i < num_packets; i++) {
        buffer[0] = (char) ((i >> 8) & 0xFF);
        buffer[1] = (char) (i & 0xFF);
        if (sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("failed to send udp packet, low entropy");
            free(cf);
            close(sockfd);
            exit(1);
        }
    }
    sleep(interval_time);
    char random[payload_size];
    get_random_byte(payload_size, random);

    printf("Sending high entropy packets...\n");
    for (int i = 0; i < num_packets; i++) {
        random[0] = (char) ((i >> 8) & 0xFF);
        random[1] = (char) (i & 0xFF);

        if (sendto(sockfd, random, sizeof(random), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("failed to send udp packet, high entropy");
            free(cf);
            close(sockfd);
            exit(1);
        }
    }
    sleep(interval_time);
    close(sockfd);
}

/**
 * Receives the message from the server
 * @param cf configuration struct
 */
void post_probe_receiver(struct config* cf) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("failed to create socket");
        exit(EXIT_FAILURE);
    }

    struct hostent *new_server = gethostbyname(cf->server_ip);
    if (new_server == NULL) {
        perror("failed to get host");
        free(cf);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serv_addr;
    int port = (int) strtol(cf->post_probe_port, NULL, 10);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(cf->server_ip);
    serv_addr.sin_port = htons(port);


    int optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("Error setting socket options");
        exit(EXIT_FAILURE);
    }

    if (connect(sockfd, (const struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("failed to connect");
        free(cf);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    char message[BUF_SIZE];

    int n = read(sockfd, message, BUF_SIZE);
    if (n < 0) {
        perror("failed to read message");
        free(cf);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("message: %s\n", message);
    close(sockfd);

}

/**
 * Main function
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char** argv) {
    char* file_path = argv[1];
    FILE* file = fopen(file_path, "r");
    struct config* cf = (struct config*) malloc(sizeof(struct config));
    cJSON* root = read_file_config(file);
    get_configuration(cf, root); // retrieve the configuration data from the JSON object

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd == -1) {
        perror("failed to create socket");
        exit(EXIT_FAILURE);
    }
    pre_probe_sender(cf, root, file, sockfd);

    sleep(1);

    // send the udp packet
    int new_sockfd_udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket creation failed");
        exit(1);
    }
    probing_udp_sender(cf, new_sockfd_udp);
    post_probe_receiver(cf);

    free(cf);
    return 0;
}