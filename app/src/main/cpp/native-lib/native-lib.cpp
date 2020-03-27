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
