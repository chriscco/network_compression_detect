#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/errno.h>
#include <string.h>
#include <sys/time.h>
#include <signal.h>

#include "config.h"
#include "cJSON.h"

#define BUF_SIZE 1024
#define TIMEOUT_SEC 10

volatile int exit_loop_low = 0;
volatile int exit_loop_high = 0;

void set_exit_flag_low(int signal) {
    exit_loop_low = 1;
}

void set_exit_flag_high(int signal) {
    exit_loop_high = 1;
}


/**
 * Accepts a connection from the client and receives the configuration
 * @param port pre-probe port
 * @param cf configuration struct
 * @param root JSON object
 */
void pre_probe_conn_accept(int port, struct config* cf, cJSON* root) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        free(cf);
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);


    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error binding, in pre_probe");
        free(cf);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    if (listen(sockfd, 5) < 0) {
        perror("Error listening");
        free(cf);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_sock;
    while (1) {
        client_sock = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("Error accepting connection");
            free(cf);
            close(sockfd);
            exit(EXIT_FAILURE);
        }
        char buffer[BUF_SIZE];
        int n = (int) recv(client_sock, &buffer, BUF_SIZE, 0);
        if (n < 0) {
            perror("Error receiving data");
            free(cf);
            close(sockfd);
            exit(EXIT_FAILURE);
        }
        buffer[n] = '\0';
        root = cJSON_Parse(buffer);
        get_configuration(cf, root);
        break;
    }
    close(client_sock);
    close(sockfd);
}

/**
 * Get the time difference between the high and low entropy packets
 * It is the place where server receives all the packets
 * @param cf configuration struct
 * @param time_diff time difference between high and low entropy packets
 */
void probing_phase(struct config* cf, double* time_diff) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        free(cf);
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons((int) strtol(cf->dst_port_udp, NULL, 10));
    socklen_t addr_len = sizeof(server_addr);


    if(bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error binding, in probing");
        free(cf);
        close(sockfd);
        exit(EXIT_FAILURE);
    }


    int payload_size = (int) strtol(cf->udp_payload_size, NULL, 10);
    int packet_num = (int) strtol(cf->num_udp_packets, NULL, 10);
    struct timeval high_start_time, high_end_time, low_start_time, low_end_time;
    char buffer[payload_size];

    int timeout = 10;
    struct timeval tv;
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
        perror("Setting socket timeout failed");
        exit(EXIT_FAILURE);
    }

    printf("Receiving low entropy packets...\n");
    for (int i = 0; i < packet_num && exit_loop_low == 0; i++) {
        bzero(buffer, payload_size);
        int n = (int) recvfrom(sockfd, buffer, payload_size, 0,
                               (struct sockaddr *)&server_addr, &addr_len);
        if (i == 0 && n > 0) {
            gettimeofday(&low_start_time, NULL);
            alarm(TIMEOUT_SEC);
            signal(SIGALRM, set_exit_flag_low);
        }
    }

    gettimeofday(&low_end_time, NULL);
    double time_interval_low = (double) (low_end_time.tv_usec - low_start_time.tv_usec) / 1000000 +
                               (double) (low_end_time.tv_sec - low_start_time.tv_sec);
    printf("Time interval low: %f\n", time_interval_low);

    sleep(10);

    printf("Receiving high entropy packets...\n");
    for (int i = 0; i < packet_num && exit_loop_high == 0; i++) {
        bzero(buffer, payload_size);
        int n = (int) recvfrom(sockfd, buffer, payload_size, 0,
                               (struct sockaddr *)&server_addr, &addr_len);
        if (i == 0 && n > 0) {
            gettimeofday(&high_start_time, NULL);
            alarm(TIMEOUT_SEC);
            signal(SIGALRM, set_exit_flag_high);
        }
    }
    gettimeofday(&high_end_time, NULL);
    double time_interval_high = (double) (high_end_time.tv_usec - high_start_time.tv_usec) / 1000000 +
                                (double) (high_end_time.tv_sec - high_start_time.tv_sec);
    printf("Time interval high: %f\n", time_interval_high);
    *time_diff = (time_interval_high - time_interval_low) * 1000;
    printf("Time difference: %f ms\n", *time_diff);
}

/**
 * Send the result of the probing phase to the client
 * @param cf configuration struct
 * @param time_diff time difference between high and low entropy packets
 */
void post_probe_sender(struct config* cf, double time_diff) {
    int port = (int) strtol(cf->post_probe_port, NULL, 10);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Error creating socket");
        free(cf);
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);


    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Error binding");
        free(cf);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    if (listen(sockfd, 5) < 0) {
        perror("Error listening");
        free(cf);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    int cli_sock = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
    if (cli_sock < 0) {
        perror("Error accepting connection");
        free(cf);
        close(sockfd);
        close(cli_sock);
        exit(EXIT_FAILURE);
    }
    char buffer[BUF_SIZE];
    if (time_diff > 100) {
        strncpy(buffer, "Compression detected", sizeof(buffer) - 1);
    } else {
        strncpy(buffer, "No compression detected", sizeof(buffer) - 1);
    }
    buffer[sizeof buffer - 1] = '\0';
    if (write(cli_sock, buffer, strlen(buffer) + 1) < 0) {
        perror("Error writing to socket");
        free(cf);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    printf("Result {%s} sent to client\n", buffer);
    close(cli_sock);
    close(sockfd);
}


/**
 * Main function
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char** argv) {
    int tcp_port = (int) strtol(argv[1], NULL, 10);

    cJSON *root = NULL;
    struct config* cf = (struct config*) malloc(sizeof(struct config));
    if (cf == NULL) {
        perror("Error allocating memory for config struct");
        exit(EXIT_FAILURE);
    }
    printf("Waiting For Configuration...\n");
    pre_probe_conn_accept(tcp_port, cf, root);
    cJSON_Delete(root);
    sleep(1); // sleep one sec

    double time_diff;
    probing_phase(cf, &time_diff);

    post_probe_sender(cf, time_diff);

    free(cf);

    return 0;
}