//
// Created by Chris Cao on 4/14/24.
//

#ifndef UNTITLED_CONFIG_H
#define UNTITLED_CONFIG_H

#include "cJSON.h"

struct config {
    char server_ip[20];
    char src_port_udp[20];
    char dst_port_udp[20];
    char dst_port_tcp_head[20];
    char dst_port_tcp_tail[20];
    char pre_probe_port[20];
    char post_probe_port[20];
    char udp_payload_size[20];
    char inter_measure_time[20];
    char num_udp_packets[20];
    char udp_ttl[20];
};

/**
 * get_random_byte - get random bytes from a file
 * @param payload_size
 * @param random
 */
void get_random_byte(int payload_size, char* random) {
    FILE* file = fopen("random_file", "r");
    if (file == NULL) {
        perror("failed to open random_file");
        exit(EXIT_FAILURE);
    }
    if (fread(random, 1, payload_size, file) < 0) {
        perror("failed to read random bytes");
        fclose(file);
        exit(EXIT_FAILURE);
    }
    fclose(file);
}

/**
 * read_file_config - read the configuration file
 * @param file
 * @return
 */
cJSON* read_file_config(FILE* file) {
    char* res_str = NULL;
    fseek(file, 0, SEEK_END);
    size_t file_len = ftell(file);
    fseek(file, 0, SEEK_SET);
    res_str = (char*) malloc(file_len + 1);
    fread(res_str, 1, file_len, file);
    fclose(file);
    res_str[file_len] = '\0';

    cJSON* root = cJSON_Parse(res_str);
    if (root == NULL) {
        perror("failed to parse JSON data");
        free(res_str);
        fclose(file);
        exit(EXIT_FAILURE);
    }
    free(res_str);
    return root;
}

/**
 * get_configuration - get the configuration from the JSON data
 * @param cf
 * @param root
 */
void get_configuration(struct config* cf, cJSON* root) {
    strncpy(cf->server_ip, cJSON_GetObjectItem(root, "server_ip")->valuestring,
            sizeof(cf->server_ip));
    strncpy(cf->pre_probe_port, cJSON_GetObjectItem(root, "pre_probe_port")->valuestring,
            sizeof(cf->pre_probe_port));
    strncpy(cf->post_probe_port, cJSON_GetObjectItem(root, "post_probe_port")->valuestring,
            sizeof(cf->post_probe_port));
    strncpy(cf->src_port_udp, cJSON_GetObjectItem(root, "src_port_udp")->valuestring,
            sizeof(cf->src_port_udp));
    strncpy(cf->dst_port_udp, cJSON_GetObjectItem(root, "dst_port_udp")->valuestring,
            sizeof(cf->dst_port_udp));
    strncpy(cf->dst_port_tcp_head, cJSON_GetObjectItem(root, "dst_port_tcp_head")->valuestring,
            sizeof(cf->dst_port_tcp_head));
    strncpy(cf->dst_port_tcp_tail, cJSON_GetObjectItem(root, "dst_port_tcp_tail")->valuestring,
            sizeof(cf->dst_port_tcp_tail));
    strncpy(cf->udp_payload_size, cJSON_GetObjectItem(root, "udp_payload_size")->valuestring,
            sizeof(cf->udp_payload_size));
    strncpy(cf->inter_measure_time, cJSON_GetObjectItem(root, "inter_measure_time")->valuestring,
            sizeof(cf->inter_measure_time));
    strncpy(cf->num_udp_packets, cJSON_GetObjectItem(root, "num_udp_packets")->valuestring,
            sizeof(cf->num_udp_packets));
    strncpy(cf->udp_ttl, cJSON_GetObjectItem(root, "udp_ttl")->valuestring,
            sizeof(cf->udp_ttl));
}


#endif //UNTITLED_CONFIG_H
