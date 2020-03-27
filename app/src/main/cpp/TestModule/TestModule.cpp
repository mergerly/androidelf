#include <jni.h>
#include <string>
#include <unistd.h>

#include "PrintLog.h"

int foo(int x)
{
    printf("%d\n", x);
    LOGD("foo Func is called:%d\n", x);
    return 0;
}

extern "C" __attribute__ ((visibility ("default"))) int test_entry()
{
    foo(5);
    LOGE("[TestModule] test_entry Func is called\n");
    return 0;
}

__attribute__((constructor)) void _init_array(void)
{
    int pid=getpid();
    LOGE("[TestModule]Load So _init_array function is called, __from pid:%d",pid);
}

extern "C" void _init(void) {
    int pid=getpid();
    LOGE("[TestModule]Load So _init function is called, __from pid:%d",pid);
}