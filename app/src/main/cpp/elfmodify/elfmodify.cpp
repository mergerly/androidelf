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

#include "PrintLog.h"

#define MAX_NAME_LENGTH 128

#if defined(__LP64__)
#define ELFBIT(what) Elf64_## what
#else
#define ELFBIT(what) Elf32_## what
#endif

#define    Elf_Addr    ELFBIT(Addr)
#define    Elf_Ehdr    ELFBIT(Ehdr)
#define    Elf_Phdr    ELFBIT(Phdr)
#define    Elf_Shdr    ELFBIT(Shdr)
#define    Elf_Dyn     ELFBIT(Dyn)

// 0 读取文件内容到内存
int load_file(char *filename, long *filesize, uint8_t **filebuf) {
    int ret = -1;
    FILE *fp = fopen(filename, "rb");
    if (NULL == fp) {
        LOGE("[%s:%d] %s file may couldn't be opened!, err:%s\n", __FUNCTION__, __LINE__, filename,
             strerror(errno));
        return -2;
    }

    do {
        fseek(fp, 0, SEEK_END);
        long size = ftell(fp);
        if (0x10 > size) {
            LOGE("[%s:%d]file size is error: %d", __FUNCTION__, __LINE__, size);
            break;
        }
        fseek(fp, 0, SEEK_SET);
        uint8_t *buf = (uint8_t *) malloc(size * 2);
        if (NULL == buf) {
            LOGE("[%s:%d]malloc failed, err:%s", __FUNCTION__, __LINE__, strerror(errno));
            break;
        }
        memset(buf, 0, size * 2);
        long read_count = fread(buf, sizeof(uint8_t), size, fp);
        if (read_count != size) {
            LOGE("[%s:%d]read file failed, err:%s", __FUNCTION__, __LINE__, strerror(errno));
            free(buf);
            break;
        }
        ret = 0;
        *filesize = size;
        *filebuf = buf;

    } while (0);

    fclose(fp);
    return ret;
}

bool dump_memory(void *start, size_t len) {
    char filename[MAX_NAME_LENGTH] = "/data/local/tmp/dump.bin";
    FILE *file = fopen(filename, "wb");
    if (!file) {
        printf("[Error] open file %s failed!\n", filename);
        return false;
    }
    fwrite(start, 1, len, file);
    fclose(file);
    return true;
}

size_t modify_elf(uint8_t *filebuf, size_t filesize, char *name, char *soname) {
    Elf_Ehdr *ehdr = (Elf_Ehdr *) filebuf;
    // 检查magic number是否为”\177ELF”
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
//        LOGE("\"%s\" has bad ELF magic", name);
        printf("\"%s\" has bad ELF magic\n", name);
        exit(-3);
    }

    //将程序头表移动到文件尾以便新增表项
    Elf_Phdr *phdr = (Elf_Phdr *) (filebuf + ehdr->e_phoff);
    size_t phdr_size = ehdr->e_phnum * ehdr->e_phentsize;
    memcpy(filebuf + filesize, phdr, phdr_size);
    ehdr->e_phoff = filesize;   //修正偏移
    phdr = (Elf_Phdr *) (filebuf + filesize);
    printf("[INFO] move phdr success!\n");

    //增加一个程序头表项
    Elf_Phdr *add_phdr = phdr + ehdr->e_phnum;
    ehdr->e_phnum += 1;
    size_t new_phdr_size = ehdr->e_phnum * ehdr->e_phentsize;

    // 打印内存
//    dump_memory(filebuf, filesize + new_phdr_size);

    ///////////////////////////////////////////
    //将DT_STRTAB移到文件尾并且添加新so的名字

    //找到原来的DT_STRTAB
    const char *old_strtab = NULL;
    size_t old_strtab_size = 0;
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            Elf_Dyn *dynamic = (Elf_Dyn *) (filebuf + phdr[i].p_offset);
            for (Elf_Dyn *d = dynamic; d->d_tag != DT_NULL; ++d) {
//                printf("%lX %lX\n", d->d_tag, d->d_un.d_ptr);
                if (d->d_tag == DT_STRTAB)
                    old_strtab = (char *) (filebuf + d->d_un.d_ptr);
                if (d->d_tag == DT_STRSZ)
                    old_strtab_size = d->d_un.d_val;
            }
            break;
        }
    }
    if (NULL == old_strtab) {
        printf("[INFO] can not find DT_STRTAB!\n");
        exit(-2);
    }
    printf("[INFO] get DT_STRTAB success!\n");

    // 添加新的soname到文件末尾
    char *new_strtab = (char *) (phdr + ehdr->e_phnum);
    memcpy(new_strtab, old_strtab, old_strtab_size);
    strncpy(new_strtab + old_strtab_size, soname, MAX_NAME_LENGTH);
    size_t new_strtab_size = old_strtab_size + strlen(soname) + 1;

    // 把新 DT_STRTAB 添加到新的Phdr段信息
    add_phdr->p_type = PT_LOAD;
    add_phdr->p_offset = filesize;
    add_phdr->p_vaddr = add_phdr->p_paddr = add_phdr->p_offset;
    add_phdr->p_filesz = add_phdr->p_memsz = new_phdr_size + new_strtab_size;
    add_phdr->p_flags = PF_W | PF_R;
    add_phdr->p_align = filesize;
    printf("[INFO] add PT_LOAD success!\n");
    //修改PT_PHDR中文件偏移和虚拟地址
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_PHDR) {
            phdr[i].p_offset = filesize;
            phdr[i].p_paddr = phdr[i].p_vaddr = filesize;
            phdr[i].p_filesz = phdr[i].p_memsz = ehdr->e_phnum * ehdr->e_phentsize;
            break;
        }
    }

    //修正动态信息中的DT_STRTAB
    for (int i = 0; i < ehdr->e_phnum; ++i) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            Elf_Dyn *dynamic = (Elf_Dyn *) (filebuf + phdr[i].p_offset);
            for (Elf_Dyn *d = dynamic;
                 (uint8_t *) d < (filebuf + phdr[i].p_offset + phdr[i].p_filesz); ++d) {
                if (d->d_tag == DT_STRTAB)
                    d->d_un.d_ptr = (uint8_t *) new_strtab - filebuf;
                else if (d->d_tag == DT_STRSZ)
                    d->d_un.d_val = new_strtab_size;
                else if (d->d_tag == DT_NULL) {
                    //添加动态库到一个空节
                    d->d_tag = DT_NEEDED;
                    d->d_un.d_ptr = new_strtab + old_strtab_size - new_strtab;
                    printf("[INFO] add DT_NEEDED success!\n");
                    break;
                }
            }
            break;
        }
    }
    printf("[INFO] modify DT_STRTAB success!\n");

    // 修正Section
    Elf_Shdr *shdr = (Elf_Shdr *) (filebuf + ehdr->e_shoff);
    for (int i = 0; i < ehdr->e_shnum; ++i) {
        if (shdr[i].sh_type == SHT_STRTAB) {
            shdr[i].sh_addr = (uint8_t *) new_strtab - filebuf;
            shdr[i].sh_offset = (uint8_t *) new_strtab - filebuf;
            shdr[i].sh_size = new_strtab_size;
            break;
        }
    }
    printf("[INFO] modify SECTION success!\n");

    dump_memory(filebuf, filesize + new_phdr_size + new_strtab_size);
    return filesize + new_phdr_size + new_strtab_size;
}


bool modify_file_test() {
    char filename[MAX_NAME_LENGTH] = "/data/local/tmp/libnative-lib.so";
//    char filename[MAX_NAME_LENGTH] = "/data/local/tmp/exectest";
    char soname[MAX_NAME_LENGTH] = "/data/local/tmp/libTestModule.so";
    long filesize = 0;
    char cmdline[MAX_NAME_LENGTH] = {0};
    uint8_t *filebuf = NULL;
    bool ret = false;

    printf("[INFO] start modify [%s] add [%s] !\n", filename, soname);

    // 0 读取文件内容到内存
    if (0 != load_file(filename, &filesize, &filebuf)) {
        printf("[%s:%d] load file error:%s", __FUNCTION__, __LINE__, strerror(errno));
        return false;
    }

    //修改内存文件
    size_t new_file_size = modify_elf(filebuf, filesize, filename, soname);

#if 1
    // 备份原文件
    char bak_filename[MAX_NAME_LENGTH] = {0};
    strncpy(bak_filename, filename, MAX_NAME_LENGTH);
    strcat(bak_filename, ".bak");
    int bak_ret = rename(filename, bak_filename);
    if (bak_ret != 0) {
        printf("[Error] backup %s file failed!\n", filename);
        exit(-1);
    }

    //写入新文件
    FILE *newfile = fopen(filename, "wb");
    if (!newfile) {
        printf("[Error] open file %s failed!\n", filename);
        exit(-1);
    }
    fwrite(filebuf, 1, new_file_size + 2, newfile);
    fclose(newfile);
#endif
    return ret;
}

int main(int argc, char **argv) {
    modify_file_test();
    return 0;
}