#include <stdio.h>
#include <stdlib.h>


int main(void)
{
  char *test;

  
  
  printf(" *** main @ %08x\n", main);
  printf(" *** printf @ %08x\n", printf);
  printf(" *** calloc @ %08x\n", calloc);

  while(1) {
    test = calloc(0x1000, sizeof(char));
    test[0] = 'B';
    printf(" *** test: 4 KBytes allocated @ %08x\n", test);
    getchar();
    test[100] = 'C';
    test[1000] = 'A';
  }
  return 0;
}
