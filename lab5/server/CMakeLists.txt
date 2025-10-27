cmake_minimum_required(VERSION 3.10)
project(c_sha_server C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(exe server)

add_executable(${exe} src/main.c src/sha1.c src/streebog.c)
add_executable(client src/client.c)

add_executable(gost3410_signer
    src/gost3410.cpp
    src/streebog.c
)
target_include_directories(gost3410_signer PRIVATE src)
