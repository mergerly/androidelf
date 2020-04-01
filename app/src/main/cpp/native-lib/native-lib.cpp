#include <jni.h>
#include <string>
#include <dlfcn.h>
#include "PrintLog.h"

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_androidelf_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

extern "C" __attribute__ ((visibility ("default"))) int test_entry()
{
    LOGE("[nativelib] test_entry Func is called\n");
    return 0;
}