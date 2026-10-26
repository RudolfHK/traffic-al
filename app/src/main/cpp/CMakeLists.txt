cmake_minimum_required(VERSION 3.22.1)

project(trafficcapture C)

# zdtun (LGPL-3.0) provides the user-space TCP/UDP/ICMP forwarding.
add_subdirectory(zdtun)

add_library(trafficcapture SHARED
        capture_engine.c
        jni_bridge.c)

target_include_directories(trafficcapture PRIVATE zdtun)
target_compile_options(trafficcapture PRIVATE -Wall -Wextra -Wno-unused-parameter)
# Same configuration zdtun's own CMakeLists applies to its sources (Android logging).
target_compile_definitions(trafficcapture PRIVATE ANDROID)

find_library(log-lib log)
target_link_libraries(trafficcapture zdtun ${log-lib})
