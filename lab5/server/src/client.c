#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PORT 8080


void print_hashing_context(char* result, int len) {
    for (size_t i = 0; i < len; ++i)
        printf("%02x", (unsigned char)result[i]);
    printf("\n");
}


int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
    const char* msg = "SHA1  ";

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 addresses from text to binary
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }
    while (1) {
        send(sock, msg, strlen(msg), 0);
        int readed = read(sock, buffer, sizeof(buffer));
        printf("The value is: %d \n", readed);
        // printf("Server reply: %s\n", buffer);
        print_hashing_context(buffer, readed);
    }
    close(sock);
    return 0;
}
