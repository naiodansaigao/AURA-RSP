cmake_minimum_required(VERSION 3.5)
project(aura_epid_benchmark C)

add_executable(aura_epid_benchmark epid_benchmark.c)

target_include_directories(
    aura_epid_benchmark
    PRIVATE
        "${CMAKE_SOURCE_DIR}/epid/defs/include"
        "${CMAKE_SOURCE_DIR}/epid/member/include"
        "${CMAKE_SOURCE_DIR}/epid/verifier/include"
        "${CMAKE_SOURCE_DIR}/epid/util/include"
)

target_link_libraries(
    aura_epid_benchmark
    PRIVATE
        member_split
        verifier
        epid_util
        bcrypt
)

if(MINGW)
    target_compile_options(aura_epid_benchmark PRIVATE -O2 -Wno-error)
    target_link_options(aura_epid_benchmark PRIVATE -static -static-libgcc)
endif()
