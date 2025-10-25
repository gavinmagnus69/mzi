project(c_sha_server)
set(exe server)


add_executable(${exe} src/main.c)


add_executable(client src/client.c)