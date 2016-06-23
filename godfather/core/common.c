


#include "common.h"
#include "x86.h"
#include "debug.h"


void CmSetBit32(Bit32u* dword, Bit32u bit)
{
  Bit32u mask = ( 1 << bit );
  *dword = *dword | mask;
}


void CmClearBit32(Bit32u* dword, Bit32u bit)
{
  Bit32u mask = 0xFFFFFFFF;
  Bit32u sub = (1 << bit);
  mask = mask - sub;
  *dword = *dword & mask;
}


void CmClearBit16(Bit16u* word, Bit32u bit)
{
  Bit16u mask = 0xFFFF;
  Bit16u sub = (Bit16u) (1 << bit);
  mask = mask - sub;
  *word = *word & mask;
}

int wide2ansi(Bit8u* dst, Bit8u* src, Bit32u n)
{
  Bit32u cnt;

  if (!dst || !src)
    return -1;

  for (cnt = 0; cnt < n; ++cnt) {
    dst[cnt] = src[2*cnt];
    if (src[2*cnt + 1])
      break;
  }

  return cnt;
}

void CmSleep(Bit32u microseconds)
{
  
  
  Bit64u t0, t1, cycles;
  Bit32u freq;
  
  freq = 1000; 
  cycles = microseconds * (freq);
  RegRdtsc(&t0);
  do {
    RegRdtsc(&t1);
  } while (t1 < t0 + cycles);
  
  




















	








}
