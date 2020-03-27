//
// Created by haoyuanli on 2020-3-4.
//
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>
#include <elf.h>
#include <sys/mman.h>
#include <dlfcn.h>

#include "PrintLog.h"

#define ELF_MODULE_NAME_LEN 128

#define PAGE_START(x) ((x) & PAGE_MASK)
#define PAGE_OFFSET(x) ((x) & ~PAGE_MASK)
#define PAGE_END(x) PAGE_START((x) + (PAGE_SIZE-1))

#if defined(__LP64__)
#define ELFCLASS ELFCLASS64
#define ELFCLASS2 ELFCLASS32
#define ELF_R_SYM ELF64_R_SYM
#define ELF_R_TYPE ELF64_R_TYPE

#define ELFBIT(what) Elf64_## what
#define USE_RELA
#else
#define ELFCLASS ELFCLASS32
#define ELFCLASS2 ELFCLASS64
#define ELF_R_SYM ELF32_R_SYM
#define ELF_R_TYPE ELF32_R_TYPE

#define ELFBIT(what) Elf32_## what
#endif


#define    Elf_Addr    ELFBIT(Addr)
#define    Elf_Half    ELFBIT(Half)
#define    Elf_Off        ELFBIT(Off)
#define    Elf_Sword    ELFBIT(Sword)
#define    Elf_Word    ELFBIT(Word)
#define    Elf_Dyn        ELFBIT(Dyn)
#define    Elf_Rel        ELFBIT(Rel)
#define    Elf_Rela    ELFBIT(Rela)
#define    Elf_Sym        ELFBIT(Sym)
#define    Elf_Ehdr    ELFBIT(Ehdr)
#define    Elf_Phdr    ELFBIT(Phdr)
#define    Elf_Shdr    ELFBIT(Shdr)
#define    Elf_Nhdr    ELFBIT(Nhdr)

#define R_GENERIC_NONE 0 // R_*_NONE is always 0

#if defined(__x86_64__)
#define EM_ARCH EM_X86_64
#define R_GENERIC_JUMP_SLOT R_X86_64_JUMP_SLOT
#define R_GENERIC_GLOB_DAT  R_X86_64_GLOB_DAT
#define R_GENERIC_RELATIVE  R_X86_64_RELATIVE
#define R_GENERIC_IRELATIVE R_X86_64_IRELATIVE
#elif defined(__i386__)
#define EM_ARCH EM_386
#define R_GENERIC_JUMP_SLOT R_386_JMP_SLOT
#define R_GENERIC_GLOB_DAT  R_386_GLOB_DAT
#define R_GENERIC_RELATIVE  R_386_RELATIVE
#define R_GENERIC_IRELATIVE R_386_IRELATIVE
#elif defined(__arm__)
#define EM_ARCH EM_ARM
#define R_GENERIC_JUMP_SLOT R_ARM_JUMP_SLOT
#define R_GENERIC_GLOB_DAT  R_ARM_GLOB_DAT
#define R_GENERIC_RELATIVE  R_ARM_RELATIVE
#define R_GENERIC_IRELATIVE R_ARM_IRELATIVE
#elif defined(__aarch64__)
#define EM_ARCH EM_AARCH64
#define R_GENERIC_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define R_GENERIC_GLOB_DAT  R_AARCH64_GLOB_DAT
#define R_GENERIC_RELATIVE  R_AARCH64_RELATIVE
#define R_GENERIC_IRELATIVE R_AARCH64_IRELATIVE
#endif

typedef void (*linker_function_t)();

typedef struct tag_elf_soinfo {
    char name[ELF_MODULE_NAME_LEN];
    uint8_t *filebuf;
    uint_t filesize;

    //ELF Header
    Elf_Ehdr *ehdr;

    // 段表信息
    Elf_Phdr *phdr_table;     //程序段头表地址
    size_t phnum;       //程序段头数
    Elf_Addr entry;     //入口函数地址

    // 段内存信息
    Elf_Addr base;      //内存首地址
    size_t load_size;   //内存大小
    Elf_Addr load_bias;
    Elf_Phdr *phdr_header;

    //动态库信息
    Elf_Dyn *dynamic;   //动态链接段内存地址
    const char *strtab;
    size_t strtab_size;
    Elf_Sym *symtab;

    // ELF HASH
    size_t nbucket;
    size_t nchain;
    uint32_t *bucket;
    uint32_t *chain;

    // 重定位表
    Elf_Rel *plt_rel;
    size_t plt_rel_count;

    Elf_Rel *rel;
    size_t rel_count;

    // USE_RELA
    Elf_Rela *plt_rela;
    size_t plt_rela_count;

    Elf_Rela *rela;
    size_t rela_count;

    // dlopen句柄
    void *handle;
    uint32_t needed_count;

    // 初始化和销毁函数
    linker_function_t *init_array;
    size_t init_array_count;
    linker_function_t *fini_array;
    size_t fini_array_count;

    linker_function_t init_func;
    linker_function_t fini_func;
} elf_soinfo;

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

// 1 解析文件头
bool parse_header(elf_soinfo *info) {
    Elf_Ehdr *ehdr = (Elf_Ehdr *) info->filebuf;
    char *name = info->name;
    uintptr_t filesize = info->filesize;

    // 检查文件大小
    if (filesize < sizeof(*ehdr)) {
        LOGE("\"%s\" is too small to be an ELF executable. Expected at least %zu bytes, "
             "only found %zu bytes", name, sizeof(*ehdr), filesize);
        return false;
    }

    // 检查magic number是否为”\177ELF”
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
        LOGE("\"%s\" has bad ELF magic", name);
        return false;
    }

    // 检查其位数
    int elf_class = ehdr->e_ident[EI_CLASS];
    if (elf_class != ELFCLASS) {
        if (elf_class == ELFCLASS2) {
            LOGE("\"%s\" is 32-bit instead of 64-bit", name);
        } else {
            LOGE("\"%s\" has unknown ELF class: %d", name, elf_class);
        }
        return false;
    }

    // 检查so文件是否是小段字节序
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        LOGE("\"%s\" not little-endian: %d", name, ehdr->e_ident[EI_DATA]);
        return false;
    }

    //检查so文件是否为可执行文件或者是共享链接库文件
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
        LOGE("\"%s\" has unexpected e_type: %d", name, ehdr->e_type);
        return false;
    }

    //检查版本号
    if (ehdr->e_version != EV_CURRENT) {
        LOGE("\"%s\" has unexpected e_version: %d", name, ehdr->e_version);
        return false;
    }

    //检查是否是对应的架构平台
    if (ehdr->e_machine != EM_ARCH) {
        LOGE("\"%s\" has unexpected e_machine: %d", name, ehdr->e_machine);
        return false;
    }

    info->ehdr = ehdr;

    LOGI("\"%s\" parse ELF header done.", name);

    return true;
}

// 2 解析段头表信息
bool parse_program_header(elf_soinfo *info) {
    Elf_Ehdr *ehdr = info->ehdr;
    char *name = info->name;
    uintptr_t filesize = info->filesize;

    uintptr_t phdr_num = ehdr->e_phnum;
    if ((ehdr->e_phnum < 1) || (ehdr->e_phnum > (65536U / sizeof(Elf_Phdr)))) {
        LOGE("\"%s\" has invalid e_phnum: %d", name, ehdr->e_phnum);
        return false;
    }

    if (ehdr->e_phentsize != sizeof(Elf_Phdr)) {
        LOGE("\"%s\" has invalid e_phentsize", name);
        return false;
    }

    if ((ehdr->e_phoff >= filesize) ||
        (ehdr->e_phnum * sizeof(Elf_Phdr) > filesize - ehdr->e_phoff)) {
        LOGE("\"%s\" has invalid offset/size of program header table", name);
        return false;
    }

    Elf_Phdr *phdr_table = (Elf_Phdr *) ((uint8_t *) ehdr + ehdr->e_phoff);
    info->phdr_table = phdr_table;
    info->phnum = ehdr->e_phnum;
    info->entry = ehdr->e_entry;
    LOGI("\"%s\" read program header done.", name);

    return true;
}

// 3-1 解析段内存大小
size_t
phdr_table_get_load_size(const Elf_Phdr *phdr_table, size_t phdr_count, Elf_Addr *out_min_vaddr,
                         Elf_Addr *out_max_vaddr) {
    Elf_Addr min_vaddr = UINTPTR_MAX;
    Elf_Addr max_vaddr = 0;
    bool found_pt_load = false;
    size_t i = 0;

    for (i = 0; i < phdr_count; i++) {
        const Elf_Phdr *phdr = &phdr_table[i];

        if (phdr->p_type != PT_LOAD)
            continue;

        found_pt_load = true;

        if (phdr->p_vaddr < min_vaddr) min_vaddr = phdr->p_vaddr;
        if (phdr->p_vaddr + phdr->p_memsz > max_vaddr) max_vaddr = phdr->p_vaddr + phdr->p_memsz;
    }

    if (!found_pt_load)
        min_vaddr = 0;

    min_vaddr = PAGE_START(min_vaddr);
    max_vaddr = PAGE_END(max_vaddr);

    if (out_min_vaddr != NULL) *out_min_vaddr = min_vaddr;
    if (out_max_vaddr != NULL) *out_max_vaddr = max_vaddr;

    return max_vaddr - min_vaddr;
}

// 3-2 打印出内存
bool dump_memory(void *start, size_t len) {
    char filename[ELF_MODULE_NAME_LEN] = "/data/local/tmp/dump.bin";
    FILE *file = fopen(filename, "wb");
    if (!file) {
        printf("[Error] open file %s failed!\n", filename);
        return false;
    }
    fwrite(start, 1, len, file);
    fclose(file);
    return true;
}

// 3 加载segments到内存
bool layout_segments(elf_soinfo *info) {
    Elf_Ehdr *ehdr = info->ehdr;
    char *name = info->name;
    Elf_Phdr *phdr_table = info->phdr_table;
    uintptr_t filesize = info->filesize;

    // 分配内存空间
    Elf_Addr min_vaddr = 0;
    //获取program header table中所有LOAD属性的segment的大小范围
    size_t load_size = phdr_table_get_load_size(phdr_table, ehdr->e_phnum, &min_vaddr, NULL);
    if (0 == load_size) {
        LOGE("\"%s\" has no loadable segments", name);
        return false;
    }

    void *mm_start = mmap(NULL,
                          load_size,
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS,
                          -1,
                          0);
    if (mm_start == MAP_FAILED) {
        LOGE("couldn't map \"%s\" address space, %s", name, strerror(errno));
        return false;
    }

    memset(mm_start, 0, load_size);
    void *load_start = mm_start;
    Elf_Addr load_bias = (Elf_Addr) mm_start - min_vaddr;
    info->base = (Elf_Addr) mm_start;
    info->load_size = load_size;
    info->load_bias = load_bias;

    LOGI("3 \"%s\" malloc segments memory done. start:0x%lX, size:%lX, offset:0x%lX, vaddr:0x%lX",
         name, load_start,
         load_size, load_bias, min_vaddr);

    //加载segments到内存
    for (size_t i = 0; i < ehdr->e_phnum; i++) {
        const Elf_Phdr *phdr = &phdr_table[i];

        if (phdr->p_type != PT_LOAD)
            continue;

        // 文件节偏移超过文件范围则报错
        if (phdr->p_offset + phdr->p_filesz > filesize) {
            LOGE("\"%s\" has invalid segment[%zu]:"
                 "p_offset (%zx) + p_filesz (%zx) past end of %zx)",
                 name, i, phdr->p_offset, phdr->p_filesz, filesize);
            return false;
        }

        LOGD("copy file 0x%lX-0x%lX to memory 0x%lX", phdr->p_offset, phdr->p_filesz,
             phdr->p_vaddr);
        LOGD("copy file 0x%lX-0x%lX to memory 0x%lX", ehdr + phdr->p_offset, phdr->p_filesz,
             load_bias + phdr->p_vaddr);
        //拷贝段内容到分配的内存
        memcpy((char *) load_bias + phdr->p_vaddr, (char *) ehdr + phdr->p_offset, phdr->p_filesz);
    }

    dump_memory((void *) info->base, info->load_size);

    LOGI("3 \"%s\" load segments memory done.", name);

    return true;
}

// 4 找到 Program Header的位置
bool find_segments_phdr(elf_soinfo *info) {
    Elf_Ehdr *ehdr = info->ehdr;
    Elf_Phdr *phdr_table = info->phdr_table;
    Elf_Addr loaded_phdr = 0;
    Elf_Addr load_bias = info->load_bias;
    char *name = info->name;

    size_t i = 0;
    // 如果有PT_PHDR段，则直接使用
    for (const Elf_Phdr *phdr = phdr_table; phdr < phdr_table + ehdr->e_phnum; ++phdr) {
        if (phdr->p_type == PT_PHDR) {
            loaded_phdr = (Elf_Addr) load_bias + phdr->p_vaddr;
            break;
        }
    }

    if (loaded_phdr == 0) {
        for (const Elf_Phdr *phdr = phdr_table; phdr < phdr_table + ehdr->e_phnum; ++phdr) {
            if (phdr->p_type == PT_LOAD) {
                if (phdr->p_offset == 0) {
                    const Elf_Ehdr *offset_ehdr = (const Elf_Ehdr *) (load_bias + phdr->p_vaddr);
                    loaded_phdr = (Elf_Addr) ((char *) offset_ehdr + offset_ehdr->e_phoff);
                }
            }
        }
    }

    if (0 == loaded_phdr) {
        LOGE("can't find loaded phdr for \"%s\"", name);
        return false;
    }

    // 检测Program Header是否在LOAD属性的segment范围内
    for (const Elf_Phdr *phdr = phdr_table; phdr < phdr_table + ehdr->e_phnum; ++phdr) {
        if (phdr->p_type != PT_LOAD)
            continue;
        Elf_Addr seg_start = phdr->p_vaddr + load_bias;
        Elf_Addr seg_end = phdr->p_filesz + seg_start;
        if (seg_start <= loaded_phdr &&
            (loaded_phdr + ehdr->e_phnum * sizeof(Elf_Phdr) <= seg_end)) {
            LOGD("find loaded phdr for \"%s\" done", name);
            info->phdr_header = (Elf_Phdr *) loaded_phdr;
            return true;
        }
    }

    LOGE("can't find loaded phdr for \"%s\"", name);
    return false;
}

// 5-2 加载动态库
bool load_dynamic(elf_soinfo *info) {
    uintptr_t i = 0;
    // Extract useful information from dynamic section.
    uint32_t needed_count = 0;
    for (Elf_Dyn *d = info->dynamic; d->d_tag != DT_NULL; ++d) {
        i++;
        LOGD("i=%d d = %lX, d[0](tag) = 0x%lX d[1](val) = 0x%lX",
             i, d, (void *) d->d_tag, (void *) d->d_un.d_val);
        switch (d->d_tag) {
            case DT_HASH:
                info->nbucket = ((uint32_t *) (info->load_bias + d->d_un.d_ptr))[0];
                info->nchain = ((uint32_t *) (info->load_bias + d->d_un.d_ptr))[1];
                info->bucket = (uint32_t *) (info->load_bias + d->d_un.d_ptr + 8);
                info->chain = (uint32_t *) (info->load_bias + d->d_un.d_ptr + 8 +
                                            info->nbucket * 4);
                break;
            case DT_STRTAB:
                info->strtab = (char *) (info->load_bias + d->d_un.d_ptr);
                break;
            case DT_STRSZ:
                info->strtab_size = d->d_un.d_val;
                break;
            case DT_SYMTAB:
                info->symtab = (Elf_Sym *) (info->load_bias + d->d_un.d_ptr);
                break;
            case DT_PLTREL:
#if defined(USE_RELA)
                if (d->d_un.d_val != DT_RELA) {
                    LOGE("unsupported DT_PLTREL in \"%s\"; expected DT_RELA", info->name);
                    return false;
                }
#else
                if (d->d_un.d_val != DT_REL) {
                    LOGE("unsupported DT_PLTREL in \"%s\"; expected DT_REL", info->name);
                    return false;
                }
#endif
                break;
            case DT_JMPREL:
#if defined(USE_RELA)
                info->plt_rela = (Elf_Rela *) (info->load_bias + d->d_un.d_ptr);
#else
                info->plt_rel = (Elf_Rel*)(info->load_bias + d->d_un.d_ptr);
#endif
                break;
            case DT_PLTRELSZ:
#if defined(USE_RELA)
                info->plt_rela_count = d->d_un.d_val / sizeof(Elf_Rela);
#else
                info->plt_rel_count = d->d_un.d_val / sizeof(Elf_Rel);
#endif
                break;
            case DT_REL:
                info->rel = (Elf_Rel *) (info->base + d->d_un.d_ptr);
                break;
            case DT_RELSZ:
                info->rel_count = d->d_un.d_val / sizeof(Elf_Rel);
                break;
            case DT_RELA:
                info->rela = reinterpret_cast<Elf_Rela *>(info->load_bias + d->d_un.d_ptr);
                break;
            case DT_RELASZ:
                info->rela_count = d->d_un.d_val / sizeof(Elf_Rela);
                break;
            case DT_NEEDED:
                ++needed_count;
                break;
            case DT_INIT:
                info->init_func = reinterpret_cast<linker_function_t>(info->load_bias +
                                                                      d->d_un.d_ptr);
                break;
            case DT_FINI:
                info->fini_func = reinterpret_cast<linker_function_t>(info->load_bias +
                                                                      d->d_un.d_ptr);
                break;
            case DT_INIT_ARRAY:
                info->init_array = reinterpret_cast<linker_function_t *>(info->load_bias +
                                                                         d->d_un.d_ptr);
                break;
            case DT_INIT_ARRAYSZ:
                info->init_array_count = static_cast<uint32_t>(d->d_un.d_val) / sizeof(Elf_Addr);
                break;
            case DT_FINI_ARRAY:
                info->fini_array = reinterpret_cast<linker_function_t *>(info->load_bias +
                                                                         d->d_un.d_ptr);
                break;
            case DT_FINI_ARRAYSZ:
                info->fini_array_count = static_cast<uint32_t>(d->d_un.d_val) / sizeof(Elf_Addr);
                break;
            default:
//                LOGE("\"%s\" unused DT entry: type %p arg %p",
//                     info->name, (void *)d->d_tag, (void *)d->d_un.d_val);
                break;
        }
    }
    LOGD("mod->base = 0x%zx, mod->strtab = 0x%p, mod->symtab = 0x%p",
         info->base, info->strtab, info->symtab);

    // Sanity checks.

    //DT_HASH 是必须的.
    if (info->nbucket == 0) {
        LOGE("empty/missing DT_HASH/DT_GNU_HASH in \"%s\" "
             "(new hash type from the future?)", info->name);
        return false;
    }
    // DT_STRTAB 是必须的.
    if (info->strtab == 0) {
        LOGE("empty/missing DT_STRTAB in \"%s\"", info->name);
        return false;
    }
    //DT_SYMTAB 是必须的.
    if (info->symtab == 0) {
        LOGE("empty/missing DT_SYMTAB in \"%s\"", info->name);
        return false;
    }

    info->needed_count = needed_count;

    return true;
}

// 5-1 获取loadable segment中的dynamic section的地址和大小
void phdr_table_get_dynamic_section(const Elf_Phdr *phdr_table,
                                    int phdr_count,
                                    Elf_Addr load_bias,
                                    Elf_Dyn **dynamic,
                                    size_t *dynamic_count) {
    const Elf_Phdr *phdr = phdr_table;
    const Elf_Phdr *phdr_limit = phdr + phdr_count;
    for (phdr = phdr_table; phdr < phdr_limit; phdr++) {
        if (phdr->p_type != PT_DYNAMIC) {
            continue;
        }
        *dynamic = (Elf_Dyn *) (load_bias + phdr->p_vaddr);
        if (dynamic_count) {
            *dynamic_count = (size_t) (phdr->p_memsz / sizeof(Elf_Dyn));
        }
        return;
    }
    *dynamic = NULL;
    if (dynamic_count) {
        *dynamic_count = 0;
    }
}

// 5 准备动态表
bool pre_link_image(elf_soinfo *info) {
    Elf_Addr base = info->load_bias;
    const Elf_Phdr *phdr_header = info->phdr_header;
    size_t phnum = info->phnum;
    size_t dynamic_count;

    //获取loadable segment中的dynamic section的地址和大小
    phdr_table_get_dynamic_section(phdr_header, phnum, base, &info->dynamic,
                                   &dynamic_count);
    if (NULL == info->dynamic) {
        LOGE("missing PT_DYNAMIC?!");
        return false;
    }
    LOGD("dynamic = %lX dynamic_count=%d \n", info->dynamic, dynamic_count);
    if (!load_dynamic(info))
        return false;
    return true;
}

// 6-4 计算hash
uint32_t elfhash(const char *_name) {
    const unsigned char *name = (const unsigned char *) _name;
    uint32_t h = 0, g;

    while (*name) {
        h = (h << 4) + *name++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }
    return h;
}

// 6-3 查找符号
static Elf_Sym *soinfo_elf_lookup(elf_soinfo *si, uint32_t hash, const char *name) {
    Elf_Sym *symtab = si->symtab;
    const char *strtab = si->strtab;

    LOGD("SEARCH %s in %s@0x%08x %08x %d",
         name, si->name, si->base, hash, hash % si->nbucket);

    for (uint32_t n = si->bucket[hash % si->nbucket]; n != 0; n = si->chain[n]) {
        Elf_Sym *s = symtab + n;
        if (strcmp(strtab + s->st_name, name)) continue;

        /* only concern ourselves with global and weak symbol definitions */
        switch (ELF_ST_BIND(s->st_info)) {
            case STB_GLOBAL:
            case STB_WEAK:
                if (s->st_shndx == SHN_UNDEF) {
                    continue;
                }

                LOGD("FOUND %s in %s (%08x) %d",
                     name, si->name, s->st_value, s->st_size);
                return s;
        }
    }

    return NULL;
}

// 6-2 重定位
Elf_Sym *
soinfo_do_lookup(elf_soinfo *si, const char *name, elf_soinfo **lsi, elf_soinfo *needed[]) {
    uint32_t elf_hash = elfhash(name);
    Elf_Sym *s = NULL;

    // 1 首先在自身模块地址获取
    s = soinfo_elf_lookup(si, elf_hash, name);
    if (s != NULL) {
        *lsi = si;
        goto done;
    }

    /* Next, look for it in the preloads list */
    // 2 在预加载的模块中查找
//    for (int i = 0; gLdPreloads[i] != NULL; i++) {
//        s = soinfo_elf_lookup(gLdPreloads[i], elf_hash, name);
//        if (s != NULL) {
//            *lsi = gLdPreloads[i];
//            goto done;
//        }
//    }

    //3 在加载进来的模块中查找
//    for (int i = 0; needed[i] != NULL; i++) {
//        LOGD("%s: looking up %s in %s",
//             si->name, name, needed[i]->name);
//        s = soinfo_elf_lookup(needed[i], elf_hash, name);
//        if (s != NULL) {
//            *lsi = needed[i];
//            goto done;
//        }
//    }

    done:
    if (s != NULL) {
        LOGI("si %s sym %s s->st_value = 0x%08x, "
             "found in %s, base = 0x%08x, load bias = 0x%08x",
             si->name, name, s->st_value,
             (*lsi)->name, (*lsi)->base, (*lsi)->load_bias);
        return s;
    }

    return NULL;
}

#if defined(USE_RELA)

static Elf_Addr get_addend(Elf_Rela *rela, Elf_Addr reloc_addr __unused) {
    return rela->r_addend;
}

#else

static Elf_Addr get_addend(Elf_Rel *rel, Elf_Addr reloc_addr) {
    if (ELF_R_TYPE(rel->r_info) == R_GENERIC_RELATIVE ||
        ELF_R_TYPE(rel->r_info) == R_GENERIC_IRELATIVE) {
        return *reinterpret_cast<Elf_Addr *>(reloc_addr);
    }
    return 0;
}

#endif

// 6-1 重定位
#if defined(USE_RELA)

bool soinfo_relocate(elf_soinfo *si, Elf_Rela *rel, size_t count,
                     elf_soinfo *needed[]) {
#else

bool soinfo_relocate(elf_soinfo *si, Elf_Rel *rel, size_t count,
                     elf_soinfo *needed[]) {
#endif
    Elf_Sym *symtab = si->symtab;
    const char *strtab = si->strtab;
    Elf_Sym *s;
    elf_soinfo *lsi;
    LOGD("[soinfo_relocate] base=0x%lX, rel=0x%lX, count=%d", si->load_bias, rel, count);

    for (size_t idx = 0; idx < count; ++idx, ++rel) {
        Elf_Word type = ELF_R_TYPE(rel->r_info);//获取重定位类型
        Elf_Word sym = ELF_R_SYM(rel->r_info);//对应的符号
        Elf_Addr reloc = static_cast<Elf_Addr>(rel->r_offset + si->load_bias);
        Elf_Addr sym_addr = 0;
        char *sym_name = NULL;
        Elf_Addr addend = get_addend(rel, reloc);

        LOGD("Processing '%s' relocation at index %d, type:%d, sym:%d", si->name, idx, type, sym);
        if (type == 0) { // R_*_NONE
            continue;
        }
        if (sym != 0) {
            sym_name = (char *) (strtab + symtab[sym].st_name);
            LOGD("soinfo_do_lookup '%s' at index %d", sym_name, idx);
            s = soinfo_do_lookup(si, sym_name, &lsi, needed);//查找符号地址
            if (s == NULL) {
                for (int i = 0; needed[i] != NULL; i++) {
                    LOGD("%s: looking up %s in %s",
                         si->name, sym_name, needed[i]->name);
                    void *func = static_cast<void *>(dlsym(needed[i]->handle, sym_name));
                    if (NULL != func) {
                        sym_addr = (Elf_Addr) func;
                        LOGD("%s: find up %s in %s, addr:%lX",
                             si->name, sym_name, needed[i]->name, func);
                        break;
                    }
                }
            } else {
                /* We got a definition.  */
                sym_addr = static_cast<Elf_Addr>(s->st_value + lsi->load_bias);
            }
        } else {
            s = NULL;
        }

        // 替换重定位地址
        switch (type) {
            case R_GENERIC_JUMP_SLOT:
                LOGI("RELO JMP_SLOT %16p <- %16p %s\n",
                     reinterpret_cast<void *>(reloc),
                     reinterpret_cast<void *>(sym_addr + addend), sym_name);

                *reinterpret_cast<Elf_Addr *>(reloc) = (sym_addr + addend);
                break;
            case R_GENERIC_GLOB_DAT:
                LOGI("RELO GLOB_DAT %16p <- %16p %s\n",
                     reinterpret_cast<void *>(reloc),
                     reinterpret_cast<void *>(sym_addr + addend), sym_name);
                *reinterpret_cast<Elf_Addr *>(reloc) = (sym_addr + addend);
                break;
            case R_GENERIC_RELATIVE:
                LOGI("RELO RELATIVE %16p <- %16p\n",
                     reinterpret_cast<void *>(reloc),
                     reinterpret_cast<void *>(si->load_bias + addend));
                *reinterpret_cast<Elf_Addr *>(reloc) = (si->load_bias + addend);
                break;
#if defined(__aarch64__)
            case R_AARCH64_ABS64:
                LOGI("RELO R_AARCH64_ABS64 %16llx <- %16llx %s\n",
                     reloc, sym_addr + addend, sym_name);
                *reinterpret_cast<Elf_Addr *>(reloc) = sym_addr + addend;
                break;
            case R_AARCH64_ABS32:
                LOGI("RELO R_AARCH64_ABS32 %16llx <- %16llx %s\n",
                     reloc, sym_addr + addend, sym_name);
                {
                    const Elf_Addr min_value = static_cast<Elf_Addr>(INT32_MIN);
                    const Elf_Addr max_value = static_cast<Elf_Addr>(UINT32_MAX);
                    if ((min_value <= (sym_addr + addend)) &&
                        ((sym_addr + addend) <= max_value)) {
                        *reinterpret_cast<Elf_Addr *>(reloc) = sym_addr + addend;
                    } else {
                        LOGE("0x%016llx out of range 0x%016llx to 0x%016llx",
                             sym_addr + addend, min_value, max_value);
                        return false;
                    }
                }
                break;
            case R_AARCH64_ABS16:
                LOGI("RELO R_AARCH64_ABS16 %16llx <- %16llx %s\n",
                     reloc, sym_addr + addend, sym_name);
                {
                    const Elf_Addr min_value = static_cast<Elf_Addr>(INT16_MIN);
                    const Elf_Addr max_value = static_cast<Elf_Addr>(UINT16_MAX);
                    if ((min_value <= (sym_addr + addend)) &&
                        ((sym_addr + addend) <= max_value)) {
                        *reinterpret_cast<Elf_Addr *>(reloc) = (sym_addr + addend);
                    } else {
                        LOGE("0x%016llx out of range 0x%016llx to 0x%016llx",
                             sym_addr + addend, min_value, max_value);
                        return false;
                    }
                }
                break;
            case R_AARCH64_PREL64:
                LOGI("RELO R_AARCH64_PREL64 %16llx <- %16llx - %16llx %s\n",
                     reloc, sym_addr + addend, rel->r_offset, sym_name);
                *reinterpret_cast<Elf_Addr *>(reloc) = sym_addr + addend - rel->r_offset;
                break;
            case R_AARCH64_PREL32:
                LOGI("RELO R_AARCH64_PREL32 %16llx <- %16llx - %16llx %s\n",
                     reloc, sym_addr + addend, rel->r_offset, sym_name);
                {
                    const Elf_Addr min_value = static_cast<Elf_Addr>(INT32_MIN);
                    const Elf_Addr max_value = static_cast<Elf_Addr>(UINT32_MAX);
                    if ((min_value <= (sym_addr + addend - rel->r_offset)) &&
                        ((sym_addr + addend - rel->r_offset) <= max_value)) {
                        *reinterpret_cast<Elf_Addr *>(reloc) = sym_addr + addend - rel->r_offset;
                    } else {
                        LOGE("0x%016llx out of range 0x%016llx to 0x%016llx",
                             sym_addr + addend - rel->r_offset, min_value, max_value);
                        return false;
                    }
                }
                break;
            case R_AARCH64_PREL16:
                LOGI("RELO R_AARCH64_PREL16 %16llx <- %16llx - %16llx %s\n",
                     reloc, sym_addr + addend, rel->r_offset, sym_name);
                {
                    const Elf_Addr min_value = static_cast<Elf_Addr>(INT16_MIN);
                    const Elf_Addr max_value = static_cast<Elf_Addr>(UINT16_MAX);
                    if ((min_value <= (sym_addr + addend - rel->r_offset)) &&
                        ((sym_addr + addend - rel->r_offset) <= max_value)) {
                        *reinterpret_cast<Elf_Addr *>(reloc) = sym_addr + addend - rel->r_offset;
                    } else {
                        LOGE("0x%016llx out of range 0x%016llx to 0x%016llx",
                             sym_addr + addend - rel->r_offset, min_value, max_value);
                        return false;
                    }
                }
                break;

            case R_AARCH64_COPY:
                /*
                 * ET_EXEC is not supported so this should not happen.
                 *
                 * http://infocenter.arm.com/help/topic/com.arm.doc.ihi0056b/IHI0056B_aaelf64.pdf
                 *
                 * Section 4.6.11 "Dynamic relocations"
                 * R_AARCH64_COPY may only appear in executable objects where e_type is
                 * set to ET_EXEC.
                 */
                LOGE(" R_AARCH64_COPY relocations are not supported");
                return false;
#elif defined(__x86_64__)
            case R_X86_64_32:
                LOGI("RELO R_X86_64_32 %08zx <- +%08zx %s", static_cast<size_t>(reloc),
                           static_cast<size_t>(sym_addr), sym_name);
                *reinterpret_cast<Elf_Addr*>(reloc) = sym_addr + addend;
                break;
              case R_X86_64_64:
                LOGI("RELO R_X86_64_64 %08zx <- +%08zx %s", static_cast<size_t>(reloc),
                           static_cast<size_t>(sym_addr), sym_name);
                *reinterpret_cast<Elf_Addr*>(reloc) = sym_addr + addend;
                break;
              case R_X86_64_PC32:
                LOGI("RELO R_X86_64_PC32 %08zx <- +%08zx (%08zx - %08zx) %s",
                           static_cast<size_t>(reloc), static_cast<size_t>(sym_addr - reloc),
                           static_cast<size_t>(sym_addr), static_cast<size_t>(reloc), sym_name);
                *reinterpret_cast<Elf_Addr*>(reloc) = sym_addr + addend - reloc;
                break;
#elif defined(__arm__)
            case R_ARM_ABS32:
                LOGI("RELO ABS %08x <- %08x %s", reloc, sym_addr, sym_name);
                *reinterpret_cast<Elf_Addr *>(reloc) += sym_addr;
                break;
            case R_ARM_REL32:
                LOGI("RELO REL32 %08x <- %08x - %08x %s",
                     reloc, sym_addr, rel->r_offset, sym_name);
                *reinterpret_cast<Elf_Addr *>(reloc) += sym_addr - rel->r_offset;
                break;
            case R_ARM_COPY:
                LOGE("%s R_ARM_COPY relocations are not supported", si->name);
                return false;
#elif defined(__i386__)
            case R_386_32:
                LOGI("RELO R_386_32 %08x <- +%08x %s", reloc, sym_addr, sym_name);
                *reinterpret_cast<Elf_Addr *>(reloc) += sym_addr;
                break;

            case R_386_PC32:
                LOGI("RELO R_386_PC32 %08x <- +%08x (%08x - %08x) %s",
                     reloc, (sym_addr - reloc), sym_addr, reloc, sym_name);
                *reinterpret_cast<Elf_Addr *>(reloc) += (sym_addr - reloc);
                break;
#elif defined(__mips__)
            case R_MIPS_REL32:
                LOGI("RELO REL32 %08x <- %08x %s",
                           reloc, sym_addr, (sym_name) ? sym_name : "*SECTIONHDR*");
                if (s) {
                    *reinterpret_cast<Elf_Addr*>(reloc) += sym_addr;
                } else {
                    *reinterpret_cast<Elf_Addr*>(reloc) += si->base;
                }
                break;
#endif /* ANDROID_*_LINKER */
            default:
                LOGE("unknown reloc type %d @ %p (%zu)", type, rel, idx);
                return false;
        }
    }
    return true;
}

// 6 加载动态库和重定位
bool elf_link(elf_soinfo *info) {

    elf_soinfo **needed = (elf_soinfo **) alloca((1 + info->needed_count) * sizeof(elf_soinfo *));
    elf_soinfo **pneeded = needed;
    //加载所有的DT_NEEDED对应的so文件
    for (Elf_Dyn *d = info->dynamic; d->d_tag != DT_NULL; ++d) {
        if (d->d_tag == DT_NEEDED) {
            const char *library_name = info->strtab + d->d_un.d_val;
            LOGI("%s needs %s", info->name, library_name);
            elf_soinfo *need_mod = new elf_soinfo;
            strncpy(need_mod->name, library_name, ELF_MODULE_NAME_LEN);
            need_mod->handle = dlopen(library_name, RTLD_NOW | RTLD_GLOBAL);
            if (need_mod->handle == NULL) {
                LOGE("could not load module \"%s\" needed by \"%s\"", library_name, info->name);
                return false;
            }
            *pneeded++ = need_mod;
        }
    }
    *pneeded = NULL;

    //修复重定位信息
#if defined(USE_RELA)
    if (info->plt_rela != NULL) {
        LOGI("[ relocating %s plta ]", info->name);
        if (!soinfo_relocate(info, info->plt_rela, info->plt_rela_count, needed)) {//修复重定位信息
            return false;
        }
    }

    if (info->rela != NULL) {
        LOGI("[ relocating %s rela]", info->name);
        if (!soinfo_relocate(info, info->rela, info->rela_count, needed)) {
            return false;
        }
    }
#else
    if (info->plt_rel != NULL) {
        LOGI("[ relocating %s plt ]", info->name);
        if (!soinfo_relocate(info, info->plt_rel, info->plt_rel_count, needed)) {//修复重定位信息
            return false;
        }
    }

    if (info->rel != NULL) {
        LOGI("[ relocating %s rel]", info->name);
        if (!soinfo_relocate(info, info->rel, info->rel_count, needed)) {
            return false;
        }
    }
#endif

    dump_memory((void *) info->base, info->load_size);
    return true;
}

// 7-1 调用函数
void call_function(const char *function_name __unused, linker_function_t function) {
    if (function == nullptr ||
        reinterpret_cast<uintptr_t>(function) == static_cast<uintptr_t>(-1)) {
        return;
    }

    LOGI("[ Call %s @ %p ]", function_name, function);
    function();
}

// 7-2 调用函数数组
void call_array(const char *array_name __unused, linker_function_t *functions,
                size_t count, bool reverse) {
    if (functions == nullptr) {
        return;
    }

    LOGD("[ Calling %s (size %zd) @ %p ]", array_name, count, functions);

    int begin = reverse ? (count - 1) : 0;
    int end = reverse ? -1 : count;
    int step = reverse ? -1 : 1;

    for (int i = begin; i != end; i += step) {
        LOGD("[ %s[%d] == %p ]", array_name, i, functions[i]);
        call_function("function", functions[i]);
    }
}

// 7 调用初始化函数
void elf_call_constructors(elf_soinfo *info) {
    call_function("DT_INIT", info->init_func);
    call_array("DT_INIT_ARRAY", info->init_array, info->init_array_count, false);
}

// 7 调用卸载函数
void elf_call_destructors(elf_soinfo *info) {
    call_array("DT_FINI_ARRAY", info->fini_array, info->fini_array_count, true);
    call_function("DT_FINI", info->fini_func);
}

//void *find_library(const char *ModuleName) {
//    FILE *fp = NULL;
//    long ModuleBaseAddr = 0;
//    char *ModulePath, *MapFileLineItem;
//    char szFileName[50] = {0};
//    char szMapFileLine[1024] = {0};
//    char szProcessInfo[1024] = {0};
//
//    // 读取"/proc/pid/maps"可以获得该进程加载的模块
//    //  枚举自身进程模块
//    snprintf(szFileName, sizeof(szFileName), "/proc/self/maps");
//
//    fp = fopen(szFileName, "r");
//
//    if (fp != NULL) {
//        while (fgets(szMapFileLine, sizeof(szMapFileLine), fp)) {
//            if (strstr(szMapFileLine, ModuleName)) {
//                MapFileLineItem = strtok(szMapFileLine, " \t"); // 基址信息
//                char *Addr = strtok(szMapFileLine, "-");
//                ModuleBaseAddr = strtoul(Addr, NULL, 16);
//                break;
//            }
//        }
//        fclose(fp);
//    }
//
//    return (void *) ModuleBaseAddr;
//}

bool call_test(elf_soinfo *info) {
    typedef void (*entrypoint_t)();
    elf_soinfo *lsi;
    Elf_Sym *s = soinfo_do_lookup(info, "test_entry", &lsi, NULL);
    entrypoint_t func = (entrypoint_t) (s->st_value + lsi->load_bias);
    if (func != NULL) {
        func();
        LOGI("call_test func success");
    }
    return true;
}

//typedef void (*entrypoint_t)();
//entrypoint_t entry_func;
//
//void run(int argc, char **argv){
////    entry_func();
////    printf("%d %s", argc, argv[0]);
//
////    void (*start)(void);
//    void* raw_args = (void*) ((uintptr_t) __builtin_frame_address(0) + (sizeof(void*))*2);
////    start = entry_func;
//    __asm__ (
//    "mov %0, %%esp\n\t"
//    "jmp *%1\n\t"
//    : : "r"(raw_args), "r"(entry_func) :
//    );
//}
//
//bool call_entry(elf_soinfo *info){
////    typedef int (*myEntryPoint)(void* raw_args);
////    myEntryPoint func = (myEntryPoint)(info->load_bias + info->entry);
////    void* raw_args = (void*) ((uintptr_t) __builtin_frame_address(0) + sizeof(void*));
////    func(raw_args);
//
//    int argc = 1;
//    char argv[1][ELF_MODULE_NAME_LEN]={{0}};
//    strncpy(argv[0], info->name, ELF_MODULE_NAME_LEN);
//    entry_func = (entrypoint_t)(info->load_bias + info->entry);
//    run(argc, (char**)argv);
//    return true;
//}

bool parser_test() {
    char filename[ELF_MODULE_NAME_LEN] = "/data/local/tmp/libTestModule.so";
//    char filename[ELF_MODULE_NAME_LEN] = "/data/local/tmp/exectest";
    long filesize = 0;
    char cmdline[ELF_MODULE_NAME_LEN] = {0};
    uint8_t *filebuf = NULL;
    bool ret = false;

    elf_soinfo info;
    // 0 读取文件内容到内存
    if (0 != load_file(filename, &filesize, &filebuf)) {
        printf("[%s:%d] load file error:%s", __FUNCTION__, __LINE__, strerror(errno));
        return false;
    }
    strncpy(info.name, filename, ELF_MODULE_NAME_LEN);
    info.filesize = filesize;
    info.filebuf = filebuf;

    LOGD("read file buf success, size:%d", filesize);

    do {
        Elf_Addr load_bias;
        Elf_Phdr *phdr = NULL;

        // 1 解析文件头
        if (!parse_header(&info))
            break;
        // 2 解析段头表
        if (!parse_program_header(&info))
            break;
        // 3 加载段信息到内存
        if (!layout_segments(&info))
            break;
        // 4 找到 Program Header的位置
        if (!find_segments_phdr(&info))
            break;
        // 5 准备动态表
        if (!pre_link_image(&info))
            break;
        // 6 重定位
        if (!elf_link(&info))
            break;
        // 7 调用构造函数
        elf_call_constructors(&info);
//        if(info.entry != NULL){
//            call_entry(&info);
//            LOGI("EntryPoint func success");
//        }
        call_test(&info);
    } while (0);

    if (filebuf != NULL) {
        free(filebuf);
    }
    LOGI("finish");
    return ret;
}

int main(int argc, char **argv) {
    parser_test();
    return 0;
}