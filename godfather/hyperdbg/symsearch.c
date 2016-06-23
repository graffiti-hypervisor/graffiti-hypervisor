


#include "symsearch.h"
#include "syms.h"
#include "debug.h"
#include "vmmstring.h"

#define MAX(p,q) (((p) >= (q)) ? (p) : (q))





static hvm_bool DicotomicSymbolSearch(hvm_address addr, Bit32s start, Bit32s end, Bit32u* index);





PSYMBOL SymbolGetFromAddress(hvm_address addr)
{
  PSYMBOL SearchedSym;
  Bit32u index;
  if(NOS == 0) {
    return  NULL;
  }
  
  if(!DicotomicSymbolSearch(addr, 0, NOS-1, &index)) {
    SearchedSym = NULL;
  } else {
    SearchedSym = &syms[index];
  }

  return SearchedSym;
}

PSYMBOL SymbolGetNearest(hvm_address addr)
{
  PSYMBOL SearchedSym;
  Bit32u index;
  if(NOS == 0) {
    return  NULL;
  }
  
  DicotomicSymbolSearch(addr, 0, NOS-1, &index);
  SearchedSym = &syms[index];

  return SearchedSym;
}


PSYMBOL SymbolGetFromName(Bit8u* name)
{
  PSYMBOL SearchedSym;
  Bit32u index;

  for(index = 0; index < NOS; index++) {
    SearchedSym = &syms[index];
    
    if(vmm_strncmpi(SearchedSym->name, name, MAX(vmm_strlen(name), vmm_strlen(SearchedSym->name))) == 0)
      return SearchedSym;
  }
  return NULL;
}


static hvm_bool DicotomicSymbolSearch(hvm_address addr, Bit32s start, Bit32s end, Bit32u* index)
{
  Bit32u mid;
  PSYMBOL CurrentSym;

  mid = (start+end)/2;
  CurrentSym = &syms[mid];

  while(end >= start) {
    if(addr == (CurrentSym->addr + hyperdbg_state.win_state.kernel_base)) {
      *index = mid;
      return TRUE;
    }

    if(addr < (CurrentSym->addr + hyperdbg_state.win_state.kernel_base)) {
      end = mid - 1;
    } else {
      start = mid + 1;
    }

    return DicotomicSymbolSearch(addr, start, end, index);
  }

  
  *index = mid;
  return FALSE; 
}
