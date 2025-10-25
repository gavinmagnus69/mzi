#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "server.h"


#define PORT 8080




int main() {
    signal(SIGINT, handle_signal);
    run_server(PORT);
    return 0;
}
