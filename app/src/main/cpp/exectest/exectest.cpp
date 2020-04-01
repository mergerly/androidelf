//
// Created by haoyuanli on 2020-3-28.
//
#include <stdio.h>
#include <dlfcn.h>

#include "PrintLog.h"

typedef int (*FUNC_test_entry)();

int test_load_library() {
    //char TestModuleName[] = "/data/local/tmp/libTestModule.so";    // 注入模块全路径
    char TestModuleName[] = "/data/local/tmp/libnative-lib.so";    // 注入模块全路径
    void *handle = dlopen(TestModuleName, RTLD_LAZY);
    if (!handle) {
        LOGE("[%s](%d) dlopen %s error:%s", __FILE__, __LINE__, TestModuleName, dlerror());
        return 0;
    }

    do {
        FUNC_test_entry entry_func = (FUNC_test_entry) dlsym(handle, "test_entry");
        if (NULL == entry_func) {
            LOGE("[%s](%d) dlsym %s error:%s", __FILE__, __LINE__, "test_entry", dlerror());
            break;
        }
        entry_func();
    } while (false);

    dlclose(handle);
    return 1;
}

int test(){
    printf("one\n");
    printf("two\n");
    LOGD("test run");
    return 0;
}
int main(){
    printf("exectest run!\n");
    test();
    test_load_library();
    return 0;
}