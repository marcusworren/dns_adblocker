#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define PORT 53
#define BUFFER_SIZE 512
#define MAX_BLOCKLIST_SIZE 120945

char* blocklist[MAX_BLOCKLIST_SIZE];

// Function to load the blocklist into memory
void load_blocklist(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open blocklist file");
        return;
    }

    char line[256];
    int index = 0;
    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#' || strlen(line) <= 1) {
            continue;
        }

        if (strncmp(line, "0.0.0.0", 7) == 0) {
            char* domain = strtok(line + 8, " \t\n"); // Extract the domain
            if (domain) {
                blocklist[index] = strdup(domain);
                index++;
            }
        }

        if (index >= MAX_BLOCKLIST_SIZE) {
            break;
        }
    }

    fclose(file);
    printf("Blocklist loaded with %d entries.\n", index);
}

// Function to check if a domain is blocked
int is_blocked(const char* domain) {
    for (int i = 0; i < MAX_BLOCKLIST_SIZE && blocklist[i] != NULL; i++) {
        if (strcmp(domain, blocklist[i]) == 0) {
            return 1; 
        }
    }
    return 0; 
}

// Function to extract domain name from DNS query
void extract_domain(unsigned char* dns_query, char* domain) {
    int i = 0, j = 0;

    while (dns_query[i] != 0) {
        int len = dns_query[i];
        i++;
        for (int k = 0; k < len; k++) {
            domain[j++] = dns_query[i + k];
        }
        i += len;
        domain[j++] = '.';
    }

    domain[j - 1] = '\0'; 
}

// Function to handle DNS query
void handle_dns_query(int sockfd, struct sockaddr_in *client_addr, char *buffer) {
    unsigned char *dns_query = buffer + 12;  // Skip the DNS header
    char domain[255];
    extract_domain(dns_query, domain);

    // Check if the domain is blocked
    if (is_blocked(domain)) {
        printf("Blocking domain: %s\n", domain);

        unsigned char response[BUFFER_SIZE];
        memset(response, 0, sizeof(response));

        // Copy the original query to the response
        memcpy(response, buffer, 12);
        response[2] = 0x81;  
        response[3] = 0x83;  

        sendto(sockfd, response, 12, 0, (struct sockaddr *)client_addr, sizeof(*client_addr));

    } else {
        // Forward the query to the real DNS server (e.g., Google's 8.8.8.8)
        struct sockaddr_in forward_addr;
        forward_addr.sin_family = AF_INET;
        forward_addr.sin_port = htons(53);
        forward_addr.sin_addr.s_addr = inet_addr("8.8.8.8");

        sendto(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&forward_addr, sizeof(forward_addr));

        socklen_t addr_len = sizeof(*client_addr);
        int len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)client_addr, &addr_len);
        sendto(sockfd, buffer, len, 0, (struct sockaddr *)client_addr, sizeof(*client_addr));
    }
}

int main() {
    int sockfd;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUFFER_SIZE];

    load_blocklist("hosts.txt"); // Adjust path to the correct hosts file

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        exit(1);
    }

    printf("DNS Server is running on port %d...\n", PORT);

    while (1) {
        socklen_t len = sizeof(client_addr);
        int n = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &len);
        if (n < 0) {
            perror("Failed to receive data");
            continue;
        }
        handle_dns_query(sockfd, &client_addr, buffer);
    }

    close(sockfd);
    return 0;
}
