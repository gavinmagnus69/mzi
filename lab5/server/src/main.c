#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>


#include "server.h"
#include "sha.h"
#include "streebog.h"


#define PORT 8080

void demo_hashes(const uint8_t* msg, size_t len) {
    uint8_t sha1_digest[SHA1_DIGEST_LENGTH];
    uint8_t streebog_digest[STREEBOG_DIGEST_LENGTH];

    sha1_hash(msg, len, sha1_digest);
    streebog_hash(msg, len, streebog_digest);

    for (size_t i = 0; i < SHA1_DIGEST_LENGTH; ++i)
        printf("%02x", sha1_digest[i]);
    printf("\n");

    for (size_t i = 0; i < STREEBOG_DIGEST_LENGTH; ++i)
        printf("%02x", streebog_digest[i]);
    printf("\n");
}


int main() {
    char message[] = "Hello, World!";
    // demo_hashes((const uint8_t*)message, strlen(message));

    // signal(SIGINT, handle_signal);
    run_server(PORT);
    return 0;
}
