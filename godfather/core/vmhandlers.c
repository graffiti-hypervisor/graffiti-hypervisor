


#include "types.h"
#include "vmhandlers.h"
#include "vt.h"
#include "events.h"
#include "debug.h"
#include "common.h"
#include "msr.h"
#include "x86.h"

#ifdef ENABLE_EPT
#include "ept.h"
#endif


static hvm_bool isIOStepping = FALSE;

EVENT_PUBLISH_STATUS HypercallSwitchOff(PEVENT_ARGUMENTS args)
{
  return HVM_SUCCESS(hvm_x86_ops.hvm_switch_off()) ? \
    EventPublishHandled : EventPublishPass;
}

void HandleCR(Bit8u crno, VtCrAccessType accesstype, hvm_bool ismemory, VtRegister gpr)
{
  EVENT_CONDITION_CR cr;
  EVENT_PUBLISH_STATUS s;
  EVENT_ARGUMENTS args;

  
  cr.crno    = crno;
  cr.iswrite = (accesstype == VT_CR_ACCESS_WRITE);
  args.EventCR.gpr = gpr;
	
  s = EventPublish(EventControlRegister, &args, &cr, sizeof(cr));  

  if (s == EventPublishHandled) {
    
    return;
  }

  
  if (!ismemory && (crno == 0 || crno == 3 || crno == 4)) {
    if (accesstype == VT_CR_ACCESS_WRITE) {
      
      void (*f)(hvm_address);      

      if (crno == 0) 
	f = hvm_x86_ops.vt_set_cr0;
      else if (crno == 3)
	f = hvm_x86_ops.vt_set_cr3;
      else
	f = hvm_x86_ops.vt_set_cr4;

      switch(gpr) {
      case VT_REGISTER_RAX:  f(context.GuestContext.rax); break;
      case VT_REGISTER_RCX:  f(context.GuestContext.rcx); break;
      case VT_REGISTER_RDX:  f(context.GuestContext.rdx); break;
      case VT_REGISTER_RBX:  f(context.GuestContext.rbx); break;
      case VT_REGISTER_RSP:  f(context.GuestContext.rsp); break;
      case VT_REGISTER_RBP:  f(context.GuestContext.rbp); break;
      case VT_REGISTER_RSI:  f(context.GuestContext.rsi); break;
      case VT_REGISTER_RDI:  f(context.GuestContext.rdi); break;
      default: 
	Log("HandleCR(WRITE): unknown register %d", gpr);
	break;
      }
    } else if (accesstype == VT_CR_ACCESS_READ) {
      
      hvm_address x;

      if (crno == 0)
	x = context.GuestContext.cr0;
      else if (crno == 3)
	x = context.GuestContext.cr3;
      else
	x = context.GuestContext.cr4;

      switch(gpr) {
      case VT_REGISTER_RAX:  context.GuestContext.rax = x; break;
      case VT_REGISTER_RCX:  context.GuestContext.rcx = x; break;
      case VT_REGISTER_RDX:  context.GuestContext.rdx = x; break;
      case VT_REGISTER_RBX:  context.GuestContext.rbx = x; break;
      case VT_REGISTER_RSP:  context.GuestContext.rsp = x; break;
      case VT_REGISTER_RBP:  context.GuestContext.rbp = x; break;
      case VT_REGISTER_RSI:  context.GuestContext.rsi = x; break;
      case VT_REGISTER_RDI:  context.GuestContext.rdi = x; break;
      default: 
	Log("HandleCR(READ): unknown register %d", gpr);
	break;
      }
    }
  }
}

void HandleHLT(void)
{
  EVENT_CONDITION_NONE none;

  EventPublish(EventHlt, NULL, &none, sizeof(none));
}

void HandleIO(Bit16u port, hvm_bool isoutput, Bit8u size, hvm_bool isstring, hvm_bool isrep)
{
  EVENT_IO_DIRECTION dir;
  EVENT_CONDITION_IO io;
  EVENT_PUBLISH_STATUS s;
  EVENT_ARGUMENTS args;

  
  dir  = isoutput ? EventIODirectionOut : EventIODirectionIn;
  io.direction = dir;
  io.portnum   = port;

  
  args.EventIO.size = size;
  args.EventIO.isstring = isstring;
  args.EventIO.isrep = isrep;

  
  s = EventPublish(EventIO, &args, &io, sizeof(io));

  if (s != EventPublishHandled) {
    

    isIOStepping = TRUE;
    
    
    hvm_x86_ops.vt_trap_io(FALSE);

    
    context.GuestContext.resumerip = context.GuestContext.rip;

    
    hvm_x86_ops.vt_switch_mtf(TRUE);
  }
}

void HandleVMCALL(void)
{
  EVENT_CONDITION_HYPERCALL event;
  EVENT_PUBLISH_STATUS s;

  Log("VMCALL #%.8x detected", context.GuestContext.rax);

  event.hypernum = context.GuestContext.rax;
  s = EventPublish(EventHypercall, NULL, &event, sizeof(event));

  if (s == EventPublishNone || s == EventPublishPass) {
    
    hvm_x86_ops.hvm_inject_hw_exception(TRAP_INVALID_OP, HVM_DELIVER_NO_ERROR_CODE);
    
    Log("Invalid opcode exception injected");

    context.GuestContext.resumerip = context.GuestContext.rip;
  }
}


void HandleVMLAUNCH(void)
{
  
  hvm_x86_ops.hvm_inject_hw_exception(TRAP_INVALID_OP, HVM_DELIVER_NO_ERROR_CODE);

  
  context.GuestContext.resumerip = context.GuestContext.rip;
}

void HandleNMI(Bit32u trap, Bit32u error_code, Bit32u qualification)
{
  EVENT_PUBLISH_STATUS s;
  EVENT_CONDITION_EXCEPTION e;
  
  switch (trap) {
  case TRAP_PAGE_FAULT:
  case TRAP_INT3:
  case TRAP_DEBUG:
    break;
  default:
    
    Log("Unexpected exception/NMI #%.8x", trap);
    return;
  }

  
  e.exceptionnum = trap;

  s = EventPublish(EventException, NULL, &e, sizeof(e));
  
  if (s == EventPublishNone || s == EventPublishPass) {

    
    hvm_x86_ops.hvm_inject_hw_exception(trap, error_code);

    
    context.GuestContext.resumerip = context.GuestContext.rip;

    
    if (trap == TRAP_PAGE_FAULT) {
      
      RegSetCr2(qualification);
    }
  }
}

void HandleMTF(void)
{
  EVENT_CONDITION_NONE none;
  EVENT_PUBLISH_STATUS s;

  if(isIOStepping) {
    
    hvm_x86_ops.vt_trap_io(FALSE);
    
    hvm_x86_ops.vt_switch_mtf(FALSE);
    isIOStepping = FALSE;
    return;
  }

  s = EventPublish(EventMtf, NULL, &none, sizeof(none));

  if (s != EventPublishHandled) {
    
    hvm_x86_ops.vt_switch_mtf(FALSE);
  }
}

#ifdef ENABLE_EPT
void HandleEPTViolation(hvm_address guest_linear, hvm_address guest_phy, hvm_bool is_linear_valid, Bit8u attempt_type, hvm_bool in_page_walk, hvm_bool fill_an_entry)
{
  EVENT_CONDITION_EPT_VIOLATION event;
  EVENT_PUBLISH_STATUS s;
  EVENT_ARGUMENTS args;

  args.EventEPTViolation.guestLinearAddress = guest_linear;
  args.EventEPTViolation.guestPhysicalAddress = guest_phy;
  args.EventEPTViolation.is_linear_valid = is_linear_valid;
  args.EventEPTViolation.in_page_walk = in_page_walk;
  args.EventEPTViolation.attemptType = attempt_type;

  
  event.read = attempt_type & 0x1 ? TRUE : FALSE;
  event.write = attempt_type & 0x2 ? TRUE : FALSE;
  event.exec = attempt_type & 0x4 ? TRUE : FALSE;
  event.in_page_walk = in_page_walk;
  event.fill_an_entry = fill_an_entry;

  s = EventPublish(EventEPTViolation, &args, &event, sizeof(event));

  if (s == EventPublishNone || s == EventPublishPass) {
    
    EPTMapPhysicalAddress(guest_phy, (Bit8u)READ|WRITE|EXEC);

    
    context.GuestContext.resumerip = context.GuestContext.rip;
  }
}
#endif

