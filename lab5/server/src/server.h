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


#include "sha1.h"
#include "streebog.h"

char sha_string[] = "SHA1";
char streebog512_string[] = "STREEBOG512";


enum Hash_Type { SHA1, STREEBOG512, Unknown_Hash_Type };

struct socket_info* opened_socket = NULL;
char g_buffer[1024] = {0};

typedef struct HashingContext {
    enum Hash_Type hash_type;
    const char* text_to_hash;
} HashingContext;


struct socket_info {
    int server_fd;
    int new_socket;
    struct sockaddr_in address;
    socklen_t addrlen;
};


typedef struct HashResult {
    enum Hash_Type hash_type;
    uint8_t* digest;
    size_t digest_length;
} HashResult;


enum Hash_Type get_hash_type_from_string(const char* token) {
    if (strcmp(token, sha_string) == 0) {
        return SHA1;
    } else if (strcmp(token, streebog512_string) == 0) {
        return STREEBOG512;
    } else {
        fprintf(stderr, "Unknown hash type: %s\n", token);
        return Unknown_Hash_Type;
    }
}


struct HashingContext tokenize_buffer2(char* buffer) {
    struct HashingContext ctx;
    ctx.hash_type = Unknown_Hash_Type;
    ctx.text_to_hash = "";
    int current_index = 0;
    while (1) {
        if (buffer[current_index] == 0) {
        }
    }
}


struct HashingContext tokenize_buffer(char* buffer) {
    const char* delimiters = " \t\r\n";
    struct HashingContext ctx;
    ctx.hash_type = Unknown_Hash_Type;
    ctx.text_to_hash = "";
    if (buffer == NULL) {
        return ctx;
    }
    char* cursor = buffer + strspn(buffer, delimiters);
    if (*cursor == '\0') {
        return ctx;
    }
    char* hash_token = cursor;
    cursor += strcspn(cursor, delimiters);
    if (*cursor != '\0') {
        *cursor = '\0';
        ++cursor;
    }
    ctx.hash_type = get_hash_type_from_string(hash_token);
    cursor += strspn(cursor, delimiters);
    if (*cursor != '\0') {
        ctx.text_to_hash = cursor;
        char* end = cursor + strlen(cursor);
        while (end > cursor && (end[-1] == '\r' || end[-1] == '\n')) {
            --end;
            *end = '\0';
        }
    }
    return ctx;
}


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
    if (g_buffer[0] == '\0') {
        return 0;
    }
    return 1;
}


void print_hashing_context(HashResult* ctx) {
    for (size_t i = 0; i < ctx->digest_length; ++i)
        printf("%x", ctx->digest[i]);
    printf("\n");
}

struct HashResult perform_hashing(HashingContext* ctx) {
    struct HashResult result;
    result.hash_type = ctx->hash_type;
    const char* text_to_hash = ctx->text_to_hash != NULL ? ctx->text_to_hash : "";
    size_t text_length = strlen(text_to_hash);
    if (ctx->hash_type == SHA1) {
        result.digest_length = SHA1_DIGEST_LENGTH;
        result.digest = (uint8_t*)malloc(SHA1_DIGEST_LENGTH * sizeof(uint8_t));
        sha1_hash((const uint8_t*)text_to_hash, text_length, result.digest);
    } else if (ctx->hash_type == STREEBOG512) {
        result.digest_length = STREEBOG_DIGEST_LENGTH;
        result.digest = (uint8_t*)malloc(STREEBOG_DIGEST_LENGTH * sizeof(uint8_t));
        streebog_hash((const uint8_t*)text_to_hash, text_length, result.digest);
    } else {
        result.digest = NULL;
        result.digest_length = 0;
    }
    print_hashing_context(&result);
    return result;
}


void print_requested_text(const char* text) {
    printf("Requested text: %s\n", text != NULL ? text : "");
}


void run_server(u_int16_t server_port) {
    opened_socket = open_socket(server_port);
    accept_connection(opened_socket);
    // event loop
    while (1) {
        ssize_t bytes_read = read(opened_socket->new_socket, g_buffer, sizeof(g_buffer) - 1);
        if (bytes_read < 0) {
            perror("read failed");
            break;
        }
        if (bytes_read == 0) {
            printf("Client disconnected\n");
            break;
        }
        g_buffer[bytes_read] = '\0';
        if (!check_buffer()) {
            continue;
        }
        struct HashingContext ctx = tokenize_buffer(g_buffer);
        print_requested_text(ctx.text_to_hash);
        struct HashResult result = perform_hashing(&ctx);
        if (result.digest != NULL) {
            print_hashing_context(&result);
            send(opened_socket->new_socket, result.digest, result.digest_length, 0);
            free(result.digest);
        }
        invalidate_buffer();
    }
    close_server_socket(opened_socket);
}


#endif
