#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
int main()
{
    __int64_t * a, *b,*c,*d;
    a = (__int64_t*)malloc(0x100);
    b = (__int64_t*)malloc(0x100);
    c = (__int64_t*)malloc(0x100);
    d = (__int64_t*)malloc(0x100);
    free(a);
    free(c);
    free(d);
    d[0] = 0;
    free(b);
    printf("over");
}