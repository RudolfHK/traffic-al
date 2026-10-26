# nDPI 5.0 (LGPL-3.0): protocol and service detection. Slim build, configured like
# PCAPdroid's (see NDPI_ORIGIN.md). The configure-generated headers are in generated/.

set(NDPI_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src)

file(GLOB NDPI_SOURCES
        ${NDPI_SRC}/lib/*.c
        ${NDPI_SRC}/lib/protocols/*.c
        ${NDPI_SRC}/lib/third_party/src/*.c
        ${NDPI_SRC}/lib/third_party/src/hll/*.c)

# Not needed in the slim build (see nDPI's src/lib/Makefile.in)
list(REMOVE_ITEM NDPI_SOURCES
        ${NDPI_SRC}/lib/third_party/src/libinjection_html5.c
        ${NDPI_SRC}/lib/third_party/src/libinjection_xss.c
        ${NDPI_SRC}/lib/third_party/src/libinjection_sqli.c
        ${NDPI_SRC}/lib/third_party/src/roaring.c
        ${NDPI_SRC}/lib/third_party/src/roaring_v2.c
        ${NDPI_SRC}/lib/ndpi_bitmap.c
        ${NDPI_SRC}/lib/ndpi_bitmap64_fuse.c
        ${NDPI_SRC}/lib/ndpi_binary_bitmap.c
        ${NDPI_SRC}/lib/ndpi_filter.c)

add_library(ndpi STATIC ${NDPI_SOURCES})
set_target_properties(ndpi PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(ndpi
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/generated ${NDPI_SRC}/include
        PRIVATE ${NDPI_SRC}/lib/third_party/include)

# NDPI_SLIM changes struct layouts, so users of the headers need it too.
target_compile_definitions(ndpi PUBLIC NDPI_SLIM PRIVATE NDPI_LIB_COMPILATION)
if(ANDROID)
    target_compile_definitions(ndpi PRIVATE __bswap_64=bswap_64)
endif()

# Third-party code: do not drown our own warnings.
target_compile_options(ndpi PRIVATE -w)

if(NOT ANDROID)
    target_link_libraries(ndpi PUBLIC m)
endif()
