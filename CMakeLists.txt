cmake_minimum_required(VERSION 2.6)
project(hello_pcap)



add_executable(hello_pcap sniffex.c)

install(TARGETS hello_pcap RUNTIME DESTINATION bin)

target_link_libraries(hello_pcap pcap)