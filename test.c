#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char * argv[]){
    char v4[10] = "1234567890";
    write(0,v4,11);
    write(0,v4,11);
}