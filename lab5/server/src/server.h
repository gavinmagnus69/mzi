#ifndef src_server_h
#define src_server_h

// bool open_server_socket(int )
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct socket_info* opened_socket = NULL;
char g_buffer[1024] = {0};

struct socket_info {
    int server_fd;
    int new_socket;
    struct sockaddr_in address;
    socklen_t addrlen;
};

int accept_connection(struct socket_info* info) {
    if ((info->new_socket = accept(info->server_fd, (struct sockaddr*)&info->address, &info->addrlen)) < 0) {
        perror("accept failed");
        close(info->server_fd);
        exit(EXIT_FAILURE);
        return -1;
    }
    printf("Connection accepted from %s:%d\n", inet_ntoa(info->address.sin_addr), ntohs(info->address.sin_port));
    return 0;
}

struct socket_info* open_socket(u_int16_t port_value) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);
    char buffer[1024] = {0};
    const char* response = "Hello from macOS server!\n";

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
    address.sin_port = htons(port_value);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    struct socket_info* created_socket = (struct socket_info*)malloc(sizeof(struct socket_info));
    created_socket->server_fd = server_fd;
    created_socket->addrlen = addrlen;
    created_socket->address = address;
    printf("Server listening on port %d...\n", port_value);
    return created_socket;

    if ((new_socket = accept(server_fd, (struct sockaddr*)&address, &addrlen)) < 0) {
        perror("accept failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    printf("Connection accepted from %s:%d\n", inet_ntoa(address.sin_addr), ntohs(address.sin_port));
    // read(new_socket, buffer, sizeof(buffer));
    // printf("Client says: %s\n", buffer);
    send(new_socket, response, strlen(response), 0);

    close(new_socket);
    close(server_fd);
}

void close_server_socket(struct socket_info* sock_meta) {
    close(sock_meta->new_socket);
    close(sock_meta->server_fd);
}

void graceful_shutdown() {
    printf("Closing socket\n");
    if (opened_socket != NULL) {
        close_server_socket(opened_socket);
    }
    exit(EXIT_SUCCESS);
}

void handle_signal(int signal) {
    printf("Singal caught\n");
    graceful_shutdown();
    return;
}

void invalidate_buffer() {
    g_buffer[0] = '\0';
}

int check_buffer() {
    if(g_buffer[0] == '\0') {
        return 0;
    }
    return 1;

}




void run_server(u_int16_t server_port) {
    opened_socket = open_socket(server_port);
    accept_connection(opened_socket);
    // event loop
    while (1) {
        read(opened_socket->new_socket, g_buffer, sizeof(g_buffer));
        if(!check_buffer()) {
            continue;
        }
        printf("Client says: %s\n", g_buffer);
        invalidate_buffer();
    }
    close_server_socket(opened_socket);
}

#endif