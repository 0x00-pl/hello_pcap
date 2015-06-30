cmake_minimum_required(VERSION 2.6)
project(hello_pcap)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

add_executable(hello_pcap
sniffex.c
# encode.c
)

target_link_libraries(hello_pcap pcap)