cmake_minimum_required(VERSION 3.4.1)

enable_language(ASM)    #支持汇编
add_executable(elfmodify elfmodify.cpp )

find_library(log-lib log)

target_link_libraries(elfmodify ${log-lib} )
