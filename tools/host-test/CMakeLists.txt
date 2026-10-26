# Builds the capture engine for a Linux host (see run.sh).
cmake_minimum_required(VERSION 3.22)
project(host_capture C)

set(CPP ${CMAKE_CURRENT_SOURCE_DIR}/../../app/src/main/cpp)

# zdtun is third-party code: no warnings. It needs the host byte order.
add_library(zdtun_host STATIC ${CPP}/zdtun/zdtun.c ${CPP}/zdtun/utils.c)
target_include_directories(zdtun_host PUBLIC ${CPP}/zdtun)
target_compile_definitions(zdtun_host PUBLIC _LITTLE_ENDIAN)
target_compile_options(zdtun_host PRIVATE -w)

add_subdirectory(${CPP}/ndpi ndpi_build)

add_executable(host_capture host_capture.c ${CPP}/capture_engine.c)
target_include_directories(host_capture PRIVATE ${CPP})
target_compile_options(host_capture PRIVATE -Wall -Wextra -Werror -Wno-unused-parameter)
target_link_libraries(host_capture zdtun_host ndpi pthread)
