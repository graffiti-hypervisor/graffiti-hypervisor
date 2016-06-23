


#include "vt.h"

#define _OFFSETOF(s, m)				\
  (&(((s*)0)->m))
#define DEFINE(_sym, _val)						\
  __asm__ __volatile__ ( "\n->" #_sym " %0 " #_val : : "i" (_val) )
#define BLANK()					\
  __asm__ __volatile__ ( "\n->" : : )
#define OFFSET(_sym, _str, _mem)		\
  DEFINE(_sym, _OFFSETOF(_str, _mem));

#define CONTEXT_SYMBOL(s)					\
  OFFSET(CONTEXT_##s, struct CPU_CONTEXT, GuestContext.s);

void __foo__ (void)
{
  CONTEXT_SYMBOL(rip);
  CONTEXT_SYMBOL(resumerip);
  CONTEXT_SYMBOL(rsp);
  CONTEXT_SYMBOL(cs);
  CONTEXT_SYMBOL(cr0);
  CONTEXT_SYMBOL(cr3);
  CONTEXT_SYMBOL(cr4);
  CONTEXT_SYMBOL(rflags);
  BLANK();

  CONTEXT_SYMBOL(rax);
  CONTEXT_SYMBOL(rbx);
  CONTEXT_SYMBOL(rcx);
  CONTEXT_SYMBOL(rdx);
  CONTEXT_SYMBOL(rdi);
  CONTEXT_SYMBOL(rsi);
  CONTEXT_SYMBOL(rbp);     
}
