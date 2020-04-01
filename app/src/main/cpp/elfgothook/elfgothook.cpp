//
// Created by haoyuanli on 2020-3-27.
//

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>
#include <sys/time.h>
#include <sys/mman.h>

#include "PrintLog.h"

#define MAX_NAME_LENGTH 128

#if defined(__LP64__)
#define ELFBIT(what) Elf64_## what
#define ELF_R_SYM ELF64_R_SYM
#else
#define ELFBIT(what) Elf32_## what
#define ELF_R_SYM ELF32_R_SYM
#endif

#define    Elf_Addr    ELFBIT(Addr)
#define    Elf_Ehdr    ELFBIT(Ehdr)
#define    Elf_Phdr    ELFBIT(Phdr)
#define    Elf_Dyn     ELFBIT(Dyn)
#define    Elf_Rel     ELFBIT(Rel)
#define    Elf_Rela    ELFBIT(Rela)
#define    Elf_Sym     ELFBIT(Sym)
#define    Elf_Word    ELFBIT(Word)

void *get_module_base(const char *ModuleName) {
    FILE *fp = NULL;
    long ModuleBaseAddr = 0;
    char *ModulePath, *MapFileLineItem;
    char szFileName[50] = {0};
    char szMapFileLine[1024] = {0};
    char szProcessInfo[1024] = {0};

    // 读取"/proc/pid/maps"可以获得该进程加载的模块
    //  枚举自身进程模块
    snprintf(szFileName, sizeof(szFileName), "/proc/self/maps");


    fp = fopen(szFileName, "r");

    if (fp != NULL) {
        while (fgets(szMapFileLine, sizeof(szMapFileLine), fp)) {
            if (strstr(szMapFileLine, ModuleName)) {
                MapFileLineItem = strtok(szMapFileLine, " \t"); // 基址信息
                char *Addr = strtok(szMapFileLine, "-");
                ModuleBaseAddr = strtoul(Addr, NULL, 16);

                break;
            }
        }

        fclose(fp);
    }

    return (void *) ModuleBaseAddr;
}

Elf_Addr get_func_addr(Elf_Addr module_base, const char *func_name, char *soname) {
    Elf_Ehdr *ehdr = (Elf_Ehdr *) module_base;
    // 检查magic number是否为”\177ELF”
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
//        LOGE("\"%s\" has bad ELF magic", name);
        printf("\"%s\" has bad ELF magic\n", soname);
        exit(-3);
    }

    // 获取程序表头
    Elf_Phdr *phdr = (Elf_Phdr *) (module_base + ehdr->e_phoff);

    const char *strtab = NULL;
    Elf_Sym *symtab = NULL;
    Elf_Rel *plt_rel = NULL;
    size_t plt_rel_count;
    Elf_Rela *plt_rela = NULL;
    size_t plt_rela_count;
    bool use_rela = false;
    //查找链接表里面的字符串表和重定位表
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            Elf_Dyn *dynamic = (Elf_Dyn *) (module_base + phdr[i].p_vaddr);
            for (Elf_Dyn *d = dynamic; d->d_tag != DT_NULL; ++d) {
//                printf("%lX %lX\n", d->d_tag, d->d_un.d_ptr);
                switch (d->d_tag) {
                    case DT_STRTAB:
                        strtab = (char *) (module_base + d->d_un.d_ptr);
                        break;
                    case DT_SYMTAB:
                        symtab = (Elf_Sym *) (module_base + d->d_un.d_ptr);
                        break;
                    case DT_PLTREL:
                        if (d->d_un.d_val == DT_RELA)
                            use_rela = true;
                        else if (d->d_un.d_val == DT_REL)
                            use_rela = false;
                        else {
                            printf("Error of DT_PLTREL");
                            exit(-1);
                        }
                        break;
                    case DT_JMPREL:
                        plt_rela = (Elf_Rela *) (module_base + d->d_un.d_ptr);
                        plt_rel = (Elf_Rel *) (module_base + d->d_un.d_ptr);
                        break;
                    case DT_PLTRELSZ:
                        plt_rela_count = d->d_un.d_val / sizeof(Elf_Rela);
                        plt_rel_count = d->d_un.d_val / sizeof(Elf_Rel);
                        break;
                }
            }
            break;
        }
    }
    if (NULL == strtab) {
        printf("[INFO] can not find DT_STRTAB!\n");
        exit(-2);
    }
    printf("[INFO] get DT_STRTAB success! use_rela is %d\n", use_rela);
    if (use_rela) {
        for (int i = 0; i < plt_rela_count; ++i) {
            Elf_Word sym = ELF_R_SYM(plt_rela[i].r_info);
            char *sym_name = (char *) (strtab + symtab[sym].st_name);
            if (strcmp(sym_name, func_name) == 0) {
                return module_base + plt_rela[i].r_offset;
            }
        }
    } else {
        for (int i = 0; i < plt_rel_count; ++i) {
            Elf_Word sym = ELF_R_SYM(plt_rel[i].r_info);
            const char *sym_name = strtab + symtab[sym].st_name;
//            printf("%s\n", sym_name);
            if (strcmp(sym_name, func_name) == 0) {
                printf("find function %s\n", func_name);
                return module_base + plt_rel[i].r_offset;
            }
        }
    }
    return 0;
}

int (*old_gettimeofday)(struct timeval *tv, struct timezone *tz);

int new_gettimeofday(struct timeval *tv, struct timezone *tz) {
    printf("[+] GSLab gettimeofday GOT Hack OK\n");
    sleep(3);
    return old_gettimeofday(tv, tz);
}

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

int got_hook(char* soname, char* funcname, void* new_function, void** old_function){
    int ret = -1;
    printf("[INFO] start hook [%s] function [%s] !\n", soname, funcname);

    Elf_Addr module_base = (Elf_Addr) get_module_base(soname);
    if (0 == module_base) {
        printf("can't find module %s", soname);
        return false;
    }
    Elf_Addr func_addr = (Elf_Addr) get_func_addr(module_base, funcname, soname);
    if(0 == func_addr){
        printf("get %s addr error", funcname);
        return false;
    }
    printf("get %s addr success is 0x%lX\n", funcname, func_addr);
    *(Elf_Addr*)(old_function) = *(Elf_Addr*)func_addr;
    printf("old gettimeofday addr is 0x%lX\n", old_gettimeofday);

    int pagesize = getpagesize();
    Elf_Addr mem_page_start = func_addr & (~(pagesize - 1));
    int mret = mprotect((void *) mem_page_start, (pagesize), PROT_READ | PROT_WRITE | PROT_EXEC);
    if(mret == -1)
    {
        LOGE("[-] mprotect error");
        return false;
    }
    *(Elf_Addr*)(func_addr) = (Elf_Addr)(new_function);
    mprotect((void*)mem_page_start, pagesize, PROT_READ | PROT_EXEC);

    return ret;
}
int got_hook_test() {
    char soname[MAX_NAME_LENGTH] = "elfgothook";
    char funcname[MAX_NAME_LENGTH] = "gettimeofday";
    int ret = -1;

    ret = got_hook(soname, funcname, (void*)new_gettimeofday, (void**)&old_gettimeofday);
    return ret;
}

int main(int argc, char **argv) {
    foo();
    got_hook_test();
    foo();
    return 0;
}