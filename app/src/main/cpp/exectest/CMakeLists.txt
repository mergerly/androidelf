cmake_minimum_required(VERSION 3.4.1)

add_executable(exectest exectest.cpp )

find_library(log-lib log)

target_link_libraries(exectest ${log-lib} )
