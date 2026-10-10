#define _GNU_SOURCE
#include "parental-control-dns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <json-c/json.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define PC_DNS_CONFIG "/etc/parental-control/devices.json"
#define PC_DNS_PACKET_SIZE 65535
#define PC_DNS_TIMEOUT 3

static int udp_fd[PC_DNS_MAX_DEVICES];
static int tcp_fd[PC_DNS_MAX_DEVICES];
static unsigned char listener_ready[PC_DNS_MAX_DEVICES];

static int is_ip(const char *s) {
    struct in_addr v4;
    struct in6_addr v6;
    return inet_pton(AF_INET, s, &v4) == 1 || inet_pton(AF_INET6, s, &v6) == 1;
}

static int domain_matches(const char *domain, const char *entry) {
    size_t d = strlen(domain), e = strlen(entry);
    if (d == e) return strcasecmp(domain, entry) == 0;
    return d > e && domain[d - e - 1] == '.' && strcasecmp(domain + d - e, entry) == 0;
}

/* The configuration is atomically replaced by the main daemon when a profile changes.
 * Read it per request to avoid accessing the daemon's mutable json-c objects from a thread.
 */
static int blocked_for_device(int index, const char *domain) {
    json_object *root = json_object_from_file(PC_DNS_CONFIG);
    if (!root) return 0;
    json_object *devices = NULL, *entries = NULL;
    int blocked = 0;
    if (json_object_object_get_ex(root, "devices", &devices) &&
        json_object_is_type(devices, json_type_array) &&
        index < (int)json_object_array_length(devices)) {
        json_object *device = json_object_array_get_idx(devices, index), *field = NULL;
        int enabled = !json_object_object_get_ex(device, "enabled", &field) || json_object_get_boolean(field);
        int blacklist = json_object_object_get_ex(device, "blacklist_enabled", &field) && json_object_get_boolean(field);
        if (enabled && blacklist && json_object_object_get_ex(device, "blacklist_entries", &entries) &&
            json_object_is_type(entries, json_type_array)) {
            for (int i = 0; i < (int)json_object_array_length(entries); i++) {
                json_object *value = json_object_array_get_idx(entries, i);
                if (!json_object_is_type(value, json_type_string)) continue;
                const char *entry = json_object_get_string(value);
                if (entry && !is_ip(entry) && domain_matches(domain, entry)) {
                    blocked = 1;
                    break;
                }
            }
        }
    }
    json_object_put(root);
    return blocked;
}

/* Parse the first uncompressed DNS question; leave unusual or malformed queries
 * to the upstream resolver instead of accidentally blocking unrelated names.
 */
static int question_name(const unsigned char *packet, size_t size, char out[254], size_t *question_end) {
    if (size < 17 || packet[2] & 0x80 || packet[4] != 0 || packet[5] != 1) return 0;
    size_t pos = 12, used = 0;
    while (pos < size) {
        unsigned n = packet[pos++];
        if (n == 0) {
            if (used == 0 || pos + 4 > size) return 0;
            out[used] = 0;
            *question_end = pos + 4;
            return 1;
        }
        if (n > 63 || pos + n > size || used + n + 1 >= 254) return 0;
        if (used) out[used++] = '.';
        for (unsigned j = 0; j < n; j++) {
            unsigned char ch = packet[pos++];
            if (!(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') &&
                !(ch >= '0' && ch <= '9') && ch != '-') return 0;
            out[used++] = (char)ch;
        }
    }
    return 0;
}

static size_t denied_reply(unsigned char *packet, size_t question_end) {
    packet[2] = (unsigned char)(0x80 | (packet[2] & 0x01)); /* QR, RD */
    packet[3] = 0x83; /* RA, NXDOMAIN */
    memset(packet + 6, 0, 6); /* no answer, authority, or additional records */
    return question_end;
}

static void timeout_socket(int fd) {
    struct timeval timeout = {.tv_sec = PC_DNS_TIMEOUT};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

static int upstream_socket(int kind) {
    int fd = socket(AF_INET, kind, 0);
    if (fd < 0) return -1;
    timeout_socket(fd);
    struct sockaddr_in upstream = {.sin_family = AF_INET, .sin_port = htons(53)};
    upstream.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&upstream, sizeof(upstream)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int transfer_all(int fd, unsigned char *buffer, size_t size, int writing) {
    size_t done = 0;
    while (done < size) {
        ssize_t n = writing ? send(fd, buffer + done, size - done, MSG_NOSIGNAL) :
                              recv(fd, buffer + done, size - done, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        done += (size_t)n;
    }
    return 0;
}

static void udp_request(int device_index) {
    unsigned char packet[PC_DNS_PACKET_SIZE];
    struct sockaddr_storage client;
    socklen_t client_len = sizeof(client);
    ssize_t size = recvfrom(udp_fd[device_index], packet, sizeof(packet), 0,
                            (struct sockaddr *)&client, &client_len);
    if (size <= 0) return;
    char domain[254];
    size_t end = 0;
    if (question_name(packet, (size_t)size, domain, &end) && blocked_for_device(device_index, domain)) {
        size_t reply_size = denied_reply(packet, end);
        sendto(udp_fd[device_index], packet, reply_size, 0, (struct sockaddr *)&client, client_len);
        return;
    }
    int upstream = upstream_socket(SOCK_DGRAM);
    if (upstream < 0) return;
    if (send(upstream, packet, (size_t)size, 0) == size) {
        uint16_t id = (uint16_t)((packet[0] << 8) | packet[1]);
        ssize_t reply_size = recv(upstream, packet, sizeof(packet), 0);
        if (reply_size >= 12 && id == (uint16_t)((packet[0] << 8) | packet[1]))
            sendto(udp_fd[device_index], packet, (size_t)reply_size, 0,
                   (struct sockaddr *)&client, client_len);
    }
    close(upstream);
}

static void tcp_request(int device_index) {
    int client = accept(tcp_fd[device_index], NULL, NULL);
    if (client < 0) return;
    timeout_socket(client);
    unsigned char len_buf[2], packet[PC_DNS_PACKET_SIZE];
    if (transfer_all(client, len_buf, 2, 0) != 0) goto done;
    size_t size = ((size_t)len_buf[0] << 8) | len_buf[1];
    if (size < 12 || size > sizeof(packet) || transfer_all(client, packet, size, 0) != 0) goto done;
    char domain[254];
    size_t end = 0;
    if (question_name(packet, size, domain, &end) && blocked_for_device(device_index, domain)) {
        size_t reply_size = denied_reply(packet, end);
        len_buf[0] = (unsigned char)(reply_size >> 8);
        len_buf[1] = (unsigned char)reply_size;
        if (transfer_all(client, len_buf, 2, 1) == 0) transfer_all(client, packet, reply_size, 1);
        goto done;
    }
    int upstream = upstream_socket(SOCK_STREAM);
    if (upstream < 0) goto done;
    if (transfer_all(upstream, len_buf, 2, 1) == 0 &&
        transfer_all(upstream, packet, size, 1) == 0 &&
        transfer_all(upstream, len_buf, 2, 0) == 0) {
        size_t reply_size = ((size_t)len_buf[0] << 8) | len_buf[1];
        if (reply_size >= 12 && reply_size <= sizeof(packet) &&
            transfer_all(upstream, packet, reply_size, 0) == 0 &&
            transfer_all(client, len_buf, 2, 1) == 0)
            transfer_all(client, packet, reply_size, 1);
    }
    close(upstream);
done:
    close(client);
}

static int listening_socket(int kind, int port) {
    int fd = socket(AF_INET6, kind, 0);
    if (fd < 0) return -1;
    int both = 0, one = 1;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &both, sizeof(both));
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in6 addr = {.sin6_family = AF_INET6, .sin6_port = htons((uint16_t)port)};
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        (kind == SOCK_STREAM && listen(fd, 8) != 0)) {
        close(fd);
        return -1;
    }
    return fd;
}

static void *dns_thread(void *unused) {
    (void)unused;
    struct pollfd fds[PC_DNS_MAX_DEVICES * 2];
    int indices[PC_DNS_MAX_DEVICES * 2];
    int count = 0;
    for (int i = 0; i < PC_DNS_MAX_DEVICES; i++) {
        if (!listener_ready[i]) continue;
        fds[count] = (struct pollfd){.fd = udp_fd[i], .events = POLLIN};
        indices[count++] = i * 2;
        fds[count] = (struct pollfd){.fd = tcp_fd[i], .events = POLLIN};
        indices[count++] = i * 2 + 1;
    }
    for (;;) {
        int n = poll(fds, (nfds_t)count, -1);
        if (n < 0) { if (errno == EINTR) continue; break; }
        for (int i = 0; i < count; i++) {
            if (fds[i].revents & POLLIN) {
                int index = indices[i] / 2;
                if (indices[i] & 1) tcp_request(index);
                else udp_request(index);
            }
        }
    }
    return NULL;
}

int pc_dns_ready(int device_index) {
    return device_index >= 0 && device_index < PC_DNS_MAX_DEVICES && listener_ready[device_index];
}

int pc_dns_start(void) {
    int available = 0;
    for (int i = 0; i < PC_DNS_MAX_DEVICES; i++) {
        udp_fd[i] = listening_socket(SOCK_DGRAM, PC_DNS_PORT_BASE + i);
        tcp_fd[i] = listening_socket(SOCK_STREAM, PC_DNS_PORT_BASE + i);
        if (udp_fd[i] < 0 || tcp_fd[i] < 0) {
            if (udp_fd[i] >= 0) close(udp_fd[i]);
            if (tcp_fd[i] >= 0) close(tcp_fd[i]);
            fprintf(stderr, "parental-control: DNS proxy port %d unavailable; domain rules for device %d disabled\n",
                    PC_DNS_PORT_BASE + i, i);
            continue;
        }
        listener_ready[i] = 1;
        available++;
    }
    if (!available) return -1;
    pthread_t thread;
    if (pthread_create(&thread, NULL, dns_thread, NULL) != 0) {
        for (int i = 0; i < PC_DNS_MAX_DEVICES; i++) {
            if (!listener_ready[i]) continue;
            close(udp_fd[i]);
            close(tcp_fd[i]);
            listener_ready[i] = 0;
        }
        return -1;
    }
    pthread_detach(thread);
    return 0;
}
