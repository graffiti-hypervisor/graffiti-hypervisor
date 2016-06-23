




#include "pill.h"





hvm_address EntryRFlags;
hvm_address EntryRAX;
hvm_address EntryRCX;
hvm_address EntryRDX;
hvm_address EntryRBX;
hvm_address EntryRSP;
hvm_address EntryRBP;
hvm_address EntryRSI;
hvm_address EntryRDI;   

hvm_address GuestStack;





hvm_status RegisterEvents(void)
{
  EVENT_CONDITION_HYPERCALL hypercall;

  
  EventInit();

  
  hypercall.hypernum = HYPERCALL_SWITCHOFF;

  if(!EventSubscribe(EventHypercall, &hypercall, sizeof(hypercall), HypercallSwitchOff)) {
    GuestLog("ERROR: Unable to register switch-off hypercall handler");
    return HVM_STATUS_UNSUCCESSFUL;
  }

  return HVM_STATUS_SUCCESS;
}


void InitVMMIDT(PIDT_ENTRY pidt)
{
  int i;
  IDT_ENTRY idte_null;
  idte_null.Selector   = RegGetCs();

  
  idte_null.Access     = (1 << 15) | (0xe << 8);

  idte_null.LowOffset  = (Bit32u) NullIDTHandler & 0xffff;
  idte_null.HighOffset = (Bit32u) NullIDTHandler >> 16;

  for (i=0; i<256; i++) {
    pidt[i] = idte_null;
  }
}

hvm_status FiniPlugin(void)
{
#ifdef ENABLE_HYPERDBG
  if (!HVM_SUCCESS(HyperDbgHostFini()))
    return HVM_STATUS_UNSUCCESSFUL;
  
  if (!HVM_SUCCESS(HyperDbgGuestFini()))
    return HVM_STATUS_UNSUCCESSFUL;
#endif

  return HVM_STATUS_SUCCESS;
}

