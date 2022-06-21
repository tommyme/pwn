#include <stdio.h>
#include <malloc.h>

int main (int argc, char *argv[])
{
  int *p = malloc(0x80);
  int *p2 = malloc(0x80);
  int *p3 = malloc(0x80);
  free(p);
  free(p);
  return 0;
}
