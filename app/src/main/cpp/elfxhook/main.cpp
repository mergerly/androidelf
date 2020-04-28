//
// Created by haoyuanli on 2020-4-9.
//
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <android/log.h>
#include "xhook/xhook.h"

void foo(void)
{
    sleep(1);

    struct timeval tv;
    struct timezone tz;
    memset(&tv, 0, sizeof(tv));
    memset(&tz, 0, sizeof(tz));
    gettimeofday(&tv, &tz);

    printf("[+] gettimeofday is %d\n", tv.tv_sec);
}


int (*old_gettimeofday)(struct timeval *tv, struct timezone *tz);
int new_gettimeofday(struct timeval *tv, struct timezone *tz) {
    printf("[+] gettimeofday GOT Hack OK\n");
    sleep(3);
    return old_gettimeofday(tv, tz);
}

int got_hook_test() {

    int ret = 0;

    xhook_enable_debug(ANDROID_LOG_DEBUG);
//    ret = got_hook(soname, funcname, (void*)new_gettimeofday, (void**)&old_gettimeofday);
    xhook_register(".*\\elfxhook", "gettimeofday", (void*)new_gettimeofday, (void**)&old_gettimeofday);
    //hook now!
    xhook_refresh(0);
    return ret;
}

int main(int argc, char **argv) {
    foo();
    got_hook_test();
    foo();
    return 0;
}