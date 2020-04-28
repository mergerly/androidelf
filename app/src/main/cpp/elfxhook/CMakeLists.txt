cmake_minimum_required(VERSION 3.4.1)

enable_language(ASM)    #支持汇编

set(XHOOK_SRC
        xhook/xhook.cpp
        xhook/xh_util.cpp
        xhook/xh_log.cpp
        xhook/xh_elf.cpp
        xhook/xh_core.cpp
        )

add_executable(elfxhook ${XHOOK_SRC} main.cpp)

find_library(log-lib log)

target_link_libraries(elfxhook ${log-lib})
