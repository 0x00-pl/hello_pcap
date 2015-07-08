cmake_minimum_required(VERSION 2.6)
project(hello_pcap)


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")


# set(CMAKE_INCLUDE_PATH "$(CMAKE_INCLUDE_PATH);external/include/")
set(external_src
external/lib/rbtree.c
)

add_executable(hello_pcap
payload_cache.c
sniffex.c
tcp_hander.c
encode.c
decode.c
${external_src}
)

target_link_libraries(hello_pcap libpcap.a)