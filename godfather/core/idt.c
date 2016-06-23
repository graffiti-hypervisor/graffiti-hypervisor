


#include "x86.h"
#include "idt.h"

void RegisterIDTHandler(Bit16u index, void (*handler) (void))
{
  IDTR tmp_idt;
  PIDT_ENTRY descriptors, pidt_entry;

  __asm__ __volatile__(
		       "sidt %0\n"
		       :"=m"(tmp_idt)
		       ::"memory"
		       );
  
  descriptors = (PIDT_ENTRY) (tmp_idt.BaseHi << 16 | tmp_idt.BaseLo);
  pidt_entry = &(descriptors[index]);
  
  
  descriptors[index] = descriptors[0x2e];
  
  pidt_entry->LowOffset  = ((hvm_address) handler) & 0xffff;
  pidt_entry->HighOffset = ((hvm_address) handler) >> 16;
}

PIDT_ENTRY GetIDTEntry(Bit8u num)
{					
  Bit32u flags;
  PIDT_ENTRY pidt_entry;
  
  
  flags = RegGetFlags();
  RegSetFlags(flags & ~FLAGS_IF_MASK);

  pidt_entry = &((PIDT_ENTRY) (RegGetIdtBase()))[num];

  
  RegSetFlags(flags);

  return pidt_entry;
}

void HookIDT(Bit8u entryno, Bit16u selector, void (*handler)(void))
{
  PIDT_ENTRY pidt_entry;

  pidt_entry = GetIDTEntry(entryno);
  
  __asm__ __volatile__(
		       "cli\n"
		       "pushal\n"
    
		       
		       "movl	%%cr0,%%eax\n"
		       "pushl	%%eax\n"
    
		       
		       "andl	$0xfffeffff,%%eax\n"
		       "movl	%%eax,%%cr0\n"
		       
		       
		       "movl	%0,%%eax\n" 
		       "movw	%1,%%cx\n" 
		       "movl	%2,%%ebx\n"
		       
		       
		       "movw	%%ax,(%%ebx)\n"   
		       "shr	$16,%%eax\n"
		       "movw	%%ax,6(%%ebx)\n" 
		       "movw	%%cx,2(%%ebx)\n" 
		       
		       
		       "popl %%eax\n"
		       "movl %%eax,%%cr0\n"

		       "popal\n"
		       "sti\n"
		       ::"m"(handler), "m"(selector), "m"(pidt_entry)
		       );
}
