#include "testso.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>

__attribute__((section("hackme"))) int myadd(int a, int  b);

int dd()
{
    printf("use function");
}

int myadd(int a, int  b)
{
    static int c = 10;

    return a + b + c;
}



//void  new_init(void) __attribute__((constructor));

void __register();
void __attribute__((constructor)) new_init(void)
{
    printf("OK1\n");
    static int a = 9; 
    static int b = 11;
    int w = 12;
    printf("a is %d \n", a);

    __register(); 
}
