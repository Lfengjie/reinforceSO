#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <math.h>
#include "elf.h"
#include "decryptSo.h"

unsigned long GetLibAddr() {
    unsigned long ret = 0;
    char name[] = "testso.so";
    char buf[4096], *temp;
    int pid;
    FILE *fp;
    pid = getpid();
    sprintf(buf, "/proc/%d/maps", pid);
    fp = fopen(buf, "r");
    if (fp == NULL) {
        puts("open failed");
        goto _error;
    }
    while (fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, name)) {
            temp = strtok(buf, "-");
            ret = strtoul(temp, NULL, 16);
            break;
        }
    }
    _error: fclose(fp);
    return ret;
}

void decrypString() {
    const char* key = "encryLinuxSokey";

    Elf64_Ehdr *elfhdr;
    Elf64_Shdr *shdr;
    unsigned long size;
    unsigned long base, offset;
    int n;
    unsigned long i;

    //从maps中读取elf文件在内存中的起始地址
    base = GetLibAddr();
    //printf("\n base %ld \n", base);
    elfhdr = (Elf64_Ehdr *) base;
    //获取要被解密的section的内存地址
    offset = elfhdr->e_shoff + base;
    //printf("\n elfhdr->e_shoff %ld \n", elfhdr->e_shoff);
    //printf("\n offset %ld \n", offset);
    //section大小
    size = elfhdr->e_entry;
    //printf("\n size %ld \n", size);
    //mprotect以页为单位（4096字节）
    n = (elfhdr->e_shoff + size) / 4096
            + ((elfhdr->e_shoff + size) % 4096 == 0 ? 0 : 1);
    
    //将内存权限改写成可写
    if (mprotect((void *) base, 4096 * n, PROT_READ | PROT_EXEC | PROT_WRITE)
            != 0) {
    }

    //解密
    int keySize = strlen(key);
     
    int curKeyIndex = 0;
    for (i = 0; i < size; ++i) {
        unsigned char *addr = (char*) (offset + i);
        unsigned char d = *addr;
        int i_true = d;
	if(i_true < 0)
	    i_true = 256 + i_true;

        if(i_true <= key[curKeyIndex])
            i_true = i_true + 255;
        int s = (unsigned char)((i_true - key[curKeyIndex]) % 255);
	if(s < 0)
	    s = 256 + s;
        *addr = (unsigned char)s;
	//printf("\n i_true %d   key[curKeyIndex] %d s %d *addr %d\n",i_true, key[curKeyIndex],s, *addr);
        printf("\n char %d %d\n", i, *addr);
        curKeyIndex = curKeyIndex + 1;
        if(curKeyIndex == keySize)
            curKeyIndex = 0;
    }

        //解密完要刷新cache！
         __clear_cache((void*)offset,(void*)(offset+size));


    if (mprotect((void *) base, 4096 * n, PROT_READ | PROT_EXEC) != 0) {

    }

}
