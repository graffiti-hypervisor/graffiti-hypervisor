


#include "hyperdbg_common.h"
#include "hyperdbg_host.h"
#include "hyperdbg_cmd.h"
#include "common.h"
#include "keyboard.h"
#include "video.h"
#include "x86.h"
#include "debug.h"
#include "vmmstring.h"
#include "gui.h"
#include "events.h"
#include "sw_bp.h"
#include "vt.h"
#include "symsearch.h"
#include "mmu.h"

#ifdef GUEST_WINDOWS
#include "winxp.h"
#endif

#include "godfather.h"
#include "ept.h"





#define HYPERDBG_HYPERCALL_SETRES    0xdead0001
#define HYPERDBG_HYPERCALL_USER      0xdead0002
#define HYPERDBG_HYPERCALL_TRACEME   0xdead0003
#define HYPERDBG_HYPERCALL_FORGETME  0xdead0004
#define HYPERDBG_HYPERCALL_VISITING  0xdead0005





#ifdef ENABLE_EPT
static EVENT_PUBLISH_STATUS HyperDbgWriteAccessHandler(PEVENT_ARGUMENTS args);
static EVENT_PUBLISH_STATUS HyperDbgExecAccessHandler(PEVENT_ARGUMENTS args);
static EVENT_PUBLISH_STATUS HyperDbgInvalidAccessHandler(PEVENT_ARGUMENTS args);
static EVENT_PUBLISH_STATUS HyperDbgViolationHandler(PEVENT_ARGUMENTS args);
#endif

static EVENT_PUBLISH_STATUS HyperDbgSwBpHandler(PEVENT_ARGUMENTS args);
static EVENT_PUBLISH_STATUS HyperDbgMTFHandler(PEVENT_ARGUMENTS args);
static EVENT_PUBLISH_STATUS HyperDbgIOHandler(PEVENT_ARGUMENTS args);

static EVENT_PUBLISH_STATUS HyperDbgCRHandler(PEVENT_ARGUMENTS args);
static EVENT_PUBLISH_STATUS HyperDbgPFHandler(PEVENT_ARGUMENTS args);
static EVENT_PUBLISH_STATUS HyperDbgHypercallUser(PEVENT_ARGUMENTS args);

static EVENT_PUBLISH_STATUS HyperDbgHypercallTraceMe(PEVENT_ARGUMENTS args);
static EVENT_PUBLISH_STATUS HyperDbgHypercallForgetMe(PEVENT_ARGUMENTS args);
static EVENT_PUBLISH_STATUS HyperDbgHypercallVisiting(PEVENT_ARGUMENTS args);

static void HyperDbgCheckWrite(void);

#ifdef GUEST_WINDOWS
#define PTE_TO_MAPPED_VA(x) ( ( x - 0xC0000000 ) << 10 )
#else
hvm_address PTE_TO_MAPPED_VA(x)
{
  PPTE processPD = GodGetProtectedProcessPageDir(GodFindProtectedProcess(context.GuestContext.cr3));
  hvm_address pa_pteBase = x & 0xfffff000;
  hvm_address ptBase;
  Bit32u pdenum, ptenum, i, j;

  for(i = 0; i < 1024; i++) {
    if (processPD[i].Present) {
      ptBase = processPD[i].PageBaseAddr << 12;
      if (ptBase == pa_pteBase) {
	pdenum = i;
	break;
      }
    }
  }

  ptenum = (ptBase - x) / 4;

  return (pdenum << 22) | (ptenum << 12);
}
#endif

static void HyperDbgEnter(void);
static void HyperDbgCommandLoop(void);





#define KEYBOARD_HISTORY_SIZE 32
Bit8u keyboard_history[KEYBOARD_HISTORY_SIZE][256];
unsigned int history_index = 0;
hvm_bool history_full = FALSE;
int current_cmd = 0;

PHY_PROTECTED protected_phy_pages[MAX_PROTECTED_PHY]; 
Bit32u protected_phy_index = 0;
Bit32u last_eflags = 0;

Bit32u count_invalid = 0;
Bit32u count_valid = 0;
Bit32u count_strange = 0;

extern Bit32u pds;
extern Bit32u pts;
extern Bit32u procs;


hvm_address selfmodifying_tobeprotected;






static EVENT_PUBLISH_STATUS HyperDbgHypercallUser(PEVENT_ARGUMENTS args)
{
  GodLog("[HyperDbgHypercallUser] Setting user_base: %08hx user_row: %d user_size: %d for CR3 %08x", context.GuestContext.rbx, context.GuestContext.rcx, context.GuestContext.rdx, context.GuestContext.cr3);
  GodUserLogSetInfo(context.GuestContext.cr3, context.GuestContext.rbx, context.GuestContext.rcx, context.GuestContext.rdx);
  return EventPublishHandled;
}

Bit64u startTime, stopTime;

static EVENT_PUBLISH_STATUS HyperDbgHypercallTraceMe(PEVENT_ARGUMENTS args)
{
  Bit32u index, found_index;
  char procname[128];
  hvm_address cr3;
  char log[128];
  hvm_status r;

  startTime = stopTime = 0;

  RegRdtsc(&startTime);

  cr3 = context.GuestContext.cr3;

  found_index = GodFindProtectedProcess(cr3);

  vmm_memset(procname, 0, sizeof(procname));
#ifdef GUEST_WINDOWS
  r = WindowsFindProcessName(cr3, procname);
#elif defined GUEST_LINUX
  hvm_address pid;
  r = ProcessFindProcessPid(cr3, &pid);
  r = ProcessGetNameByPid(cr3, pid, procname);
#endif

  GodLog("Protecting process %s [cr3: %08x]", procname, cr3);

  r = GodAddProtectedProcess(cr3, &index);
  if(r == HVM_STATUS_UNSUCCESSFUL) {
    GodPanic(log, 128, "PANIC! UNABLE TO ADD PROCESS");
  }
  GodLog("CR3: %08x HAS INDEX: %d %s", cr3, index, procname);

  GodProtectAllPTs(cr3, index);

  pds++;
  procs++;

  return EventPublishHandled;
}

static EVENT_PUBLISH_STATUS HyperDbgHypercallForgetMe(PEVENT_ARGUMENTS args)
{
  

  RegRdtsc(&stopTime);

  

  return EventPublishHandled;
}

static EVENT_PUBLISH_STATUS HyperDbgHypercallVisiting(PEVENT_ARGUMENTS args)
{
  
  hvm_status r;
  unsigned char url[1024];
  vmm_memset(url, 0x00, 1024);
  r = MmuReadVirtualRegion(context.GuestContext.cr3, context.GuestContext.rbx, url, 1024);
  if(r == HVM_STATUS_SUCCESS) {
    GodLog("Simstim is visiting: %s", url);
  }
  else {
    GodLog("Cannot read from context.GuestContext.rbx: %08x", context.GuestContext.rbx);
  }
  return EventPublishHandled;
}


static void HyperDbgEnter(void)
{
  hvm_status r;

  
  hyperdbg_state.enabled = TRUE;

  if(!VideoEnabled()) {
    r = VideoAlloc();
    if(r != HVM_STATUS_SUCCESS)
      Log("[HyperDbg] Cannot allocate video memory!");
  }

  Log("[HyperDbg] Entering HyperDbg command loop"); 

  HyperDbgCommandLoop();

  Log("[HyperDbg] Leaving HyperDbg command loop");

  hyperdbg_state.enabled = FALSE;
}

static void HyperDbgCommandLoop(void)
{
  hvm_address flags;
  Bit8u c, keyboard_buffer[256];
  Bit32s i;
  hvm_bool isMouse, exitLoop;
  exitLoop = FALSE;
    
  
  flags = RegGetFlags();
  
  RegSetFlags(flags & ~FLAGS_IF_MASK);

#if 0
  
  char *buf = "\xeb\xfe";

  Log("[HyperDbgCommandLoop] Try to inject a infinite loop on guest");
  Log("[HyperDbgCommandLoop] Guest cr3 is 0x%08hx",context.GuestContext.cr3);
  Log("[HyperDbgCommandLoop] Have to replace guest resumeip with loop code, stored in buffer %08hx", buf);

  MmuWriteVirtualRegion(context.GuestContext.cr3, context.GuestContext.rip, buf, 2);
  context.GuestContext.resumerip = context.GuestContext.rip;
#endif
  
  if (VideoEnabled()) {
    

    if (!hyperdbg_state.singlestepping)
      VideoSave();

    VideoInitShell();
  }
  
  
  hyperdbg_state.singlestepping = FALSE;  

  
  vmm_memset(keyboard_buffer, 0, sizeof(keyboard_buffer));
 
  i = 0;
  while (1) {
    if (KeyboardReadKeystroke(&c, FALSE, &isMouse) != HVM_STATUS_SUCCESS) {
      
      CmSleep(150);
      continue;
    }

    if (isMouse) {
      
      continue;
    }

    if (c == HYPERDBG_MAGIC_SCANCODE) {
      Log("[HyperDbg] Magic key detected! Disabling HyperDbg...");
      break;
    }
    c = KeyboardScancodeToKeycode(c);
    
    
    switch (c) {
    case 0:
      
      break;

    case '\b':
      
      if (i > 0) {
	keyboard_buffer[--i] = 0;
      }
      break;

    case '\n':
      
      
      vmm_memset(keyboard_history[history_index], 0, sizeof(keyboard_history[history_index]));
      vmm_strncpy((unsigned char *)(&keyboard_history[history_index]), (unsigned char *)(&keyboard_buffer), 256);
      
      if(history_index == 15 && !history_full) {
	history_full = TRUE;
      }

      history_index = (history_index + 1)%KEYBOARD_HISTORY_SIZE;
      current_cmd = history_index;
      if(history_index == 0) current_cmd = KEYBOARD_HISTORY_SIZE;

      exitLoop = HyperDbgProcessCommand(keyboard_buffer);
      i = 0;
      vmm_memset(keyboard_buffer, 0, sizeof(keyboard_buffer));
      break;

    case 0x3:
      
      if(history_full || current_cmd > 0) {
	if(current_cmd <= 0)
	  current_cmd = KEYBOARD_HISTORY_SIZE;
	else
	  current_cmd = (current_cmd - 1)%KEYBOARD_HISTORY_SIZE;
	
	vmm_memset(keyboard_buffer, 0, sizeof(keyboard_buffer));
	VideoUpdateShell(keyboard_buffer);
	vmm_strncpy((unsigned char *)(&keyboard_buffer), (unsigned char *)(&keyboard_history[current_cmd]), 256);
	i = (int) vmm_strlen(keyboard_buffer);
	VideoUpdateShell(keyboard_buffer);
      }
      break;

    case 0x4:
      
      if(history_full || current_cmd < history_index) {
	current_cmd = (current_cmd + 1)%KEYBOARD_HISTORY_SIZE;
	
	vmm_memset(keyboard_buffer, 0, sizeof(keyboard_buffer));

	VideoUpdateShell(keyboard_buffer);
	vmm_strncpy((unsigned char *)(&keyboard_buffer), (unsigned char *)(&keyboard_history[current_cmd]), 256);
	i = (int) vmm_strlen(keyboard_buffer);
	VideoUpdateShell(keyboard_buffer);
      }
      break;

    case '\t':
      
      c = ' ';
      

    default:
      
      if (i < (sizeof(keyboard_buffer)/sizeof(Bit8u)-1)) {
	keyboard_buffer[i++] = c;
      }
      break;
    } 

    
    if (VideoEnabled()) {
      VideoUpdateShell(keyboard_buffer);
    }

    if(exitLoop) {
      break; 
    }
  }

  if(VideoEnabled() && !hyperdbg_state.singlestepping) {
    
    VideoRestore();
  }

  
  
}


static EVENT_PUBLISH_STATUS HyperDbgIOHandler(PEVENT_ARGUMENTS args)
{
  Bit8u c;
  hvm_bool isMouse;

  
  if (!args || args->EventIO.size != 1 || args->EventIO.isstring || args->EventIO.isrep) {
    return EventPublishPass;
  }

  
  if (KeyboardReadKeystroke(&c, FALSE, &isMouse) != HVM_STATUS_SUCCESS) {
    
    return EventPublishPass;
  }

  
  context.GuestContext.rax = ((hvm_address) context.GuestContext.rax & 0xffffff00) | (c & 0xff);

  if (!isMouse && c == HYPERDBG_MAGIC_SCANCODE) {
    

    
    context.GuestContext.rip += hvm_x86_ops.vt_get_exit_instr_len();

    HyperDbgEnter();
  }

  return EventPublishHandled;
}

#ifdef ENABLE_EPT
static EVENT_PUBLISH_STATUS HyperDbgViolationHandler(PEVENT_ARGUMENTS args)
{
  EVENT_PUBLISH_STATUS r;
  char log[128];

  if(args->EventEPTViolation.is_linear_valid == FALSE) {
    count_invalid++;
    r = HyperDbgInvalidAccessHandler(args);
  }
  else if(args->EventEPTViolation.attemptType == 2 || args->EventEPTViolation.attemptType == 3) {

    count_valid++;

    r = HyperDbgWriteAccessHandler(args);
  }
  else if(args->EventEPTViolation.attemptType == 4) {
    r = HyperDbgExecAccessHandler(args);
  }
  else {
    GodDumpViolation(args);
    GodPanic(log, 128, "PANIC! UNHANDLED EPT VIOLATION!!!!\n");
    __asm__ __volatile__("ud2\n");
  }
  return r;
}

static EVENT_PUBLISH_STATUS HyperDbgExecAccessHandler(PEVENT_ARGUMENTS args)
{
  hvm_address pa, va;
  hvm_status r;
  Bit32u traced_index, i = 0, count_similar = 0, ii, iii, count_written = 0;
  Bit64u t0;
  Bit8u  log[256];

  pa = args->EventEPTViolation.guestPhysicalAddress & 0xfffff000;
  va = args->EventEPTViolation.guestLinearAddress & 0xfffff000;

  EPTMapPhysicalAddress(pa, READ|WRITE|EXEC);

  traced_index = GodFindTracedPage(pa);
  if(traced_index < MAX_TRACED) {
    RegRdtsc(&t0);
    GodTracedSetExecuted(traced_index, t0);

    
 
    
    
    

    

    
    EPTRemovePTperms(pa, WRITE);
  }

  context.GuestContext.resumerip = context.GuestContext.rip;
  return EventPublishHandled;
}

static EVENT_PUBLISH_STATUS HyperDbgWriteAccessHandler(PEVENT_ARGUMENTS args)
{
  hvm_address va, va_pte, pa_pte, short_phy_eip, cr3 = context.GuestContext.cr3;
  Bit32u flags, index, traced_index, i;
  hvm_phy_address phy_eip;
  Bit8u opcode_minus = 0;
  hvm_bool ignore_flag;
  char log[256];
  unsigned char instructions[1024];
  hvm_status r;
  Bit64u t0;
  PTE old;

  
  if(GodIsPtProtected(args->EventEPTViolation.guestPhysicalAddress & 0xfffff000) == FALSE) { 
    traced_index = GodFindTracedPage(args->EventEPTViolation.guestPhysicalAddress & 0xfffff000);
    if(traced_index < MAX_TRACED) {
      RegRdtsc(&t0);
      GodTracedSetWritten(traced_index, t0);

      

      
      
      


      EPTMapPhysicalAddress(args->EventEPTViolation.guestPhysicalAddress & 0xfffff000, READ|WRITE|EXEC);
      
      
      if((context.GuestContext.rip & 0xfffff000) != (args->EventEPTViolation.guestLinearAddress & 0xfffff000)) { 
	
	EPTRemovePTperms(args->EventEPTViolation.guestPhysicalAddress & 0xfffff000, EXEC);
	
	context.GuestContext.resumerip = context.GuestContext.rip; 
      }
      else {										
	
	GodLog("[HyperDbgWriteAccessHandler] Self-modifying code detected! Disabling both protection and stepping!");
	vmm_memset(instructions, 0, 1024);
	MmuReadVirtualRegion(context.GuestContext.cr3, args->EventEPTViolation.guestLinearAddress, instructions, 1024);
	GodLog("[HyperDbgWriteAccessHandler] EIP @ %08x Viol: %08x", context.GuestContext.rip, 
	       args->EventEPTViolation.guestLinearAddress);

	for(i = 0; i < 1024; i++) {
	  ComPrint("\\x%02x", instructions[i]);
	}
	ComPrint("\n");
	

	
	
	

	
	hvm_x86_ops.vt_switch_mtf(TRUE);

	selfmodifying_tobeprotected = args->EventEPTViolation.guestPhysicalAddress;
	hyperdbg_state.selfmodifying_singlestepping = TRUE;

	
	context.GuestContext.resumerip = context.GuestContext.rip;
      }
      return EventPublishHandled;
    }
    else {
      GodPanic(log, 256, "[HyperDbgWriteAccessHandler] PANIC! Nobody ever protected %08x\n", args->EventEPTViolation.guestPhysicalAddress & 0xfffff000);
    }
  }
  else {

    
    va_pte = args->EventEPTViolation.guestLinearAddress;
    pa_pte = args->EventEPTViolation.guestPhysicalAddress;
    if((pa_pte & 0x3) != 0) {
      
      
      pa_pte &= ~0x3;
      va_pte &= ~0x3;
    }
    ignore_flag = FALSE;
  
    
    r = MmuReadPhysicalRegion(pa_pte, &old, sizeof(PTE));
    if(r == HVM_STATUS_UNSUCCESSFUL) {
      GodPanic(log, 128, "[HyperDbgWriteAccessHandler] PANIC! Unable to read from phy %08hx\n", pa_pte);
    }

    
    EPTMapPhysicalAddress(pa_pte, READ|WRITE|EXEC);

    
    if(protected_phy_index >= MAX_PROTECTED_PHY) {
      GodPanic(log, 128, "PANIC! NO MORE SPACE FOR SINGLE-INSTRUCTION VIOLATIONS!\n");
    }

    if(args->EventEPTViolation.in_page_walk == 1)  
      ignore_flag = TRUE;
    
    protected_phy_pages[protected_phy_index].old = old;
    protected_phy_pages[protected_phy_index].va_pte = va_pte;
    protected_phy_pages[protected_phy_index].pa_pte = pa_pte;
    protected_phy_pages[protected_phy_index].ignore_flag = ignore_flag;
    protected_phy_index++;
  
    
    if(protected_phy_index > 1) { 

      

      hvm_x86_ops.vt_switch_mtf(TRUE);

      context.GuestContext.resumerip = context.GuestContext.rip; 
      return EventPublishHandled;
    }

    hyperdbg_state.protection_singlestepping = TRUE;
    hvm_x86_ops.vt_switch_mtf(TRUE);
    
    
    context.GuestContext.resumerip = context.GuestContext.rip;

    return EventPublishHandled;
  }
}

static EVENT_PUBLISH_STATUS HyperDbgInvalidAccessHandler(PEVENT_ARGUMENTS args)
{
  hvm_address va_pte, pa_pte, cr3 = context.GuestContext.cr3;
  hvm_bool ignore_flag;
  Bit32u flags;
  hvm_status r;
  char log[256];
  PTE old;

  va_pte = -1;
  pa_pte = args->EventEPTViolation.guestPhysicalAddress;
  ignore_flag = TRUE;

  
  

  GodLog("[HyperDbgInvalidAccessHandler] Ignoring invalid access, UN-protecting PHY: %08x [cr3: %08x]", pa_pte, cr3);

  
  EPTMapPhysicalAddress(pa_pte, READ|WRITE|EXEC);

  return EventPublishHandled; 
}
#endif


static EVENT_PUBLISH_STATUS HyperDbgSwBpHandler(PEVENT_ARGUMENTS args)
{
  hvm_bool isCr3Dipendent, isPerm, useless;
  hvm_address ours_cr3, flags, uselesss;

#ifdef GUEST_WIN_7
  hvm_status r;
  Bit8u success = 0;
#endif

  if(protected_phy_index != 0) {

    hvm_phy_address phy_eip = 0;
    hvm_address short_phy_eip = 0;
    hvm_status r;
    Bit32u index = 0;
    Bit8u log[128];

    
    GodLog("[HyperDbgSwBpHandler] Hit BP @ %08x [%08x]", context.GuestContext.rip, context.GuestContext.cr3);
    r = MmuGetPhysicalAddress(context.GuestContext.cr3, context.GuestContext.rip, &phy_eip);
    if(r == HVM_STATUS_UNSUCCESSFUL) {
      GodPanic(log, 128, "[HyperDbgSwBpHandler] PANIC! Unable to get phy rip.");
    }
    short_phy_eip = GET32L(phy_eip);
    index = GodFindBP(short_phy_eip);
    if(index == MAX_GOD_BPS) {
      GodLog("[HyperDbgSwBpHandler] BP is not GodFather's. Returing it to the guest.");
      return EventPublishPass;
    }

    
    HyperDbgCheckWrite();

    r = GodRemoveBP(index);
    if(r == HVM_STATUS_UNSUCCESSFUL) {
      GodPanic(log, 128, "[HyperDbgSwBpHandler] PANIC! Unable to remove BP!");
    }

    
    protected_phy_index = 0; 
    
    context.GuestContext.resumerip = context.GuestContext.rip;

    return EventPublishHandled;
  }

  if(hyperdbg_state.console_mode) {

    if(context.GuestContext.rip == hyperdbg_state.unlink_bp_addr) {

#ifdef GUEST_WIN_7
      r = Windows7UnlinkProc(hyperdbg_state.target_cr3, hyperdbg_state.target_pep, hyperdbg_state.target_kthread, &hyperdbg_state.dispatcher_ready_index, &success);
      if(r != HVM_STATUS_SUCCESS) Log("Error on scheduling BP");

      if(success) {
      
	r = MmuWriteVirtualRegion(context.GuestContext.cr3, hyperdbg_state.unlink_bp_addr, &hyperdbg_state.opcode_backup_unlink, sizeof(Bit8u));
      }
      
      r = MmuReadVirtualRegion(context.GuestContext.cr3, context.GuestContext.rsp, &context.GuestContext.rdi, sizeof(context.GuestContext.rdi));
      if(r != HVM_STATUS_SUCCESS) Log("[HyperDbg] Special BP failed. Unable to read rsp head.");
      context.GuestContext.rsp += 4;

      context.GuestContext.resumerip = hyperdbg_state.unlink_bp_addr+1;
#endif
    }
    else if(context.GuestContext.rip == hyperdbg_state.relink_bp_addr) {

#ifdef GUEST_WIN_7          
      if(context.GuestContext.rax + context.GuestContext.rcx == hyperdbg_state.dispatcher_ready_index) {
      
	
	r = Windows7RelinkProc(context.GuestContext.cr3, hyperdbg_state.target_kthread, hyperdbg_state.dispatcher_ready_index);
      
	
	r = MmuWriteVirtualRegion(context.GuestContext.cr3, hyperdbg_state.relink_bp_addr, &hyperdbg_state.opcode_backup_relink, sizeof(Bit8u));
      }

      
      context.GuestContext.rsp -= 4;
      r = MmuWriteVirtualRegion(context.GuestContext.cr3, context.GuestContext.rsp, &context.GuestContext.rdi, sizeof(context.GuestContext.rdi));

      context.GuestContext.resumerip = hyperdbg_state.relink_bp_addr+1;
#endif
    }
    else {

      Log("[HyperDbg] checking bp @%.8x", context.GuestContext.rip);
      
      if(SwBreakpointGetBPInfo(context.GuestContext.cr3, context.GuestContext.rip, &isCr3Dipendent, &isPerm, &ours_cr3)) {

	Log("[HyperDbg] bp is ours, %s %s", isPerm?"permanent":"", isCr3Dipendent?"and cr3dipendent":"");	
	
	context.GuestContext.resumerip = context.GuestContext.rip;

	if(!isPerm) {

	  if(isCr3Dipendent && context.GuestContext.cr3 != ours_cr3) {
	    
	    
	    goto PermBP;
	  }

	  SwBreakpointDelete(context.GuestContext.cr3, context.GuestContext.rip);

	  HyperDbgEnter();
	}
	else {
PermBP:
	  if(!isCr3Dipendent || (isCr3Dipendent && context.GuestContext.cr3 == ours_cr3)) {
	    SwBreakpointDeletePerm(context.GuestContext.cr3, context.GuestContext.rip);
	    HyperDbgEnter();
	  }

	  if(SwBreakpointGetBPInfo(context.GuestContext.cr3, context.GuestContext.rip, &useless, &useless, &uselesss)) {
	  
	    SwBreakpointDelete(ours_cr3, context.GuestContext.rip);

	    if(!hyperdbg_state.singlestepping)
	      hvm_x86_ops.vt_switch_mtf(TRUE);

	    
	    hyperdbg_state.hasPermBP = TRUE;
	    hyperdbg_state.previous_codeaddr = context.GuestContext.rip;
	    hyperdbg_state.isPermBPCr3Dipendent = isCr3Dipendent;
	    hyperdbg_state.bp_cr3 = ours_cr3;
	  }
	  else {

	    hyperdbg_state.hasPermBP = FALSE;
	  }
	}
      }
      else return EventPublishPass;

      Log("[HyperDbg] Done!");
    }
  }
  else { 
    
  }
 
  return EventPublishHandled;
}

void HyperDbgCheckWrite()
{
  char procname[128], modulename[128], log[256];
  hvm_address va, va_pte, pa_pte, cr3;
  Bit32u i, index, traced_index;
  hvm_bool ignore_flag;
  hvm_status r;
  pt_status p;
  PTE new;
  PTE old;
  Bit64u exittime = 1;

  i =  index = traced_index = 0;

  cr3 = context.GuestContext.cr3;

  
  while(i < protected_phy_index) {
    
    old = protected_phy_pages[i].old;
    va_pte = protected_phy_pages[i].va_pte;
    pa_pte = protected_phy_pages[i].pa_pte;
    ignore_flag = protected_phy_pages[i].ignore_flag;
    i++;
    
    if(ignore_flag) {
      va_pte = -1;
      
      EPTRemovePTperms(pa_pte, WRITE);
    }
    else {
      va = PTE_TO_MAPPED_VA(va_pte);
      r = MmuReadPhysicalRegion(pa_pte, &new, sizeof(PTE));
      if(r == HVM_STATUS_UNSUCCESSFUL) {
        GodPanic(log, 128, "[HyperDbgCheckWrite] PANIC! Unable to read from phy %08hx", pa_pte);
      }

      
      EPTRemovePTperms(pa_pte, WRITE);
      
      
      index = GodFindProtectedProcess(pa_pte & 0xfffff000);
      
      if(index != MAX_PROTECTED_PROCESSES) {
        
        if( (( pa_pte & 0xfff ) >> 2) > 511) {
	  
          continue;
	}

        p = GodCheckMapping(&old, &new);

	
	

	
	

        if(p == GOD_MAP) { 
          if(new.LargePage == 1)
            GodLog("[HyperDbgCheckWrite] LARGE MAP");
          else {

            
            
            

            

            EPTRemovePTperms((new.PageBaseAddr << 12), WRITE); 

            GodSetPtProtected((new.PageBaseAddr << 12)); 
                                                
            GodIncPTs(index);
            pts++;
            
          }
        }
        else {
          if(p == GOD_CHANGE_FLAG) {
            
            
            
            
          }
          if(p == GOD_CHANGE_PHY) {
            
            
            

            

            
            
            
          }
          if(p == GOD_UNMAP) {
            if(old.LargePage == 1) {
              GodLog("[HyperDbgCheckWrite] LARGE UNMAP");
            }
            else {
              
              
              

              

              EPTMapPhysicalAddress((old.PageBaseAddr << 12), READ|WRITE|EXEC);
              GodSetPtUnprotected((old.PageBaseAddr << 12));
              
              GodDecPTs(index);
              
              pts--;
            }
          }
        }
      }
      else {

        
	
        

        p = GodCheckMapping(&old, &new);

	
	

        if(p == GOD_MAP) {

          
          r = GodAddTracedPage((new.PageBaseAddr << 12), va, new, &traced_index);
          if(r == HVM_STATUS_UNSUCCESSFUL) {
            GodPanic(log, 128, "[HyperDbgCheckWrite] PANIC! Unable to add traced page!\n");
          }

          
          
          

					
          
          
          

          EPTRemovePTperms((new.PageBaseAddr << 12), WRITE); 

        }
        else if(p == GOD_CHANGE_FLAG || p == GOD_CHANGE_PHY) {
          
          
          

          if(p == GOD_CHANGE_PHY) { 
            
            traced_index = GodFindTracedPage((old.PageBaseAddr << 12));
            if(traced_index < MAX_TRACED) {
              
              
              

							
              

              GodRemoveTracedPage(traced_index);
	      GodRemoveVATracedPage(va);
              EPTMapPhysicalAddress((old.PageBaseAddr << 12), READ|WRITE|EXEC);
            }

            
            r = GodAddTracedPage((new.PageBaseAddr << 12), va, new, &traced_index);
            if(r == HVM_STATUS_UNSUCCESSFUL) {
              GodPanic(log, 128, "[HyperDbgCheckWrite] PANIC! Unable to add traced page!\n");
            }

            
            
            

						
            

            EPTRemovePTperms((new.PageBaseAddr << 12), WRITE); 

          }
	  
          else if(p == GOD_CHANGE_FLAG) {
            if(new.Writable == 1 && old.Writable == 0) { 
              r = GodAddTracedPage((new.PageBaseAddr << 12), va, new, &traced_index);
              if(r == HVM_STATUS_UNSUCCESSFUL) {
                GodPanic(log, 128, "[HyperDbgCheckWrite] PANIC! Unable to add traced page!\n");
              }

              EPTRemovePTperms((new.PageBaseAddr << 12), WRITE); 

              
              

							
              

            }
            else if(new.Writable == 0 && old.Writable == 1) { 
              traced_index = GodFindTracedPage((old.PageBaseAddr << 12));
              if(traced_index < MAX_TRACED) { 
                
                
                

								
                

                GodRemoveTracedPage(traced_index);
                EPTMapPhysicalAddress((old.PageBaseAddr << 12), READ|WRITE|EXEC);
              }
            }
          }
          else {
            GodLog("[HyperDbgCheckWrite] Do nothing");
          }
        }
        else if(p == GOD_UNMAP) {

          

          
          traced_index = GodFindTracedPage((old.PageBaseAddr << 12));
          if(traced_index < MAX_TRACED) {
            
            
            

						
            

            GodRemoveTracedPage(traced_index);
 	    
            EPTMapPhysicalAddress((old.PageBaseAddr << 12), READ|WRITE|EXEC);
          }
        }
      }
    }
  }
}


hvm_address target_pid = 0;

EVENT_PUBLISH_STATUS HyperDbgCRHandler(PEVENT_ARGUMENTS args)
{
  hvm_address cr3;
  char procname[128];
  char log[128];
  hvm_status r;
  Bit32u index, found_index;
  
  switch(args->EventCR.gpr) {
  case VT_REGISTER_RAX:  cr3 = context.GuestContext.rax; break;
  case VT_REGISTER_RCX:  cr3 = context.GuestContext.rcx; break;
  case VT_REGISTER_RDX:  cr3 = context.GuestContext.rdx; break;
  case VT_REGISTER_RBX:  cr3 = context.GuestContext.rbx; break;
  case VT_REGISTER_RSP:  cr3 = context.GuestContext.rsp; break;
  case VT_REGISTER_RBP:  cr3 = context.GuestContext.rbp; break;
  case VT_REGISTER_RSI:  cr3 = context.GuestContext.rsi; break;
  case VT_REGISTER_RDI:  cr3 = context.GuestContext.rdi; break;
  default:
    Log("[HyperDbgCRHandler] unknown register %d", args->EventCR.gpr);
    cr3 = 0;
    break;
  }

  
#define TARGET1 "iexplore.exe"


	
  


	

  
  
  
  
  
  

  
  
  
  
  
  
  
  
  

  found_index = GodFindProtectedProcess(cr3);
  
  


  vmm_memset(procname, 0, sizeof(procname));
#ifdef GUEST_WINDOWS
  r = WindowsFindProcessName(cr3, procname);
#elif defined GUEST_LINUX
  hvm_address pid;
  r = ProcessFindProcessPid(cr3, &pid);
  r = ProcessGetNameByPid(cr3, pid, procname);
#endif

  if(
		  found_index == MAX_PROTECTED_PROCESSES &&                                         
		  cr3 != 0x00185000 &&                                                              
		  (vmm_strncmpi(procname, TARGET1, vmm_strlen(TARGET1)) == 0)                       
		  
    ) {
		
    
    
    

    GodLog("Protecting process %s [cr3: %08x]", procname, cr3);

    r = GodAddProtectedProcess(cr3, &index);
    if(r == HVM_STATUS_UNSUCCESSFUL) {
      GodPanic(log, 128, "PANIC! UNABLE TO ADD PROCESS");
    }
    GodLog("CR3: %08x HAS INDEX: %d %s", cr3, index, procname);

    GodProtectAllPTs(cr3, index);

    pds++;
    procs++;
  }
  else {
    if(found_index != MAX_PROTECTED_PROCESSES && GodIsToBeRemoved(found_index)) {
      GodLog("Rimuovo processo %s\n", procname);
      GodRemoveProtectedProcess(found_index);
    }
  }

  
  
  

  
  
  

  
  
  
  
  
  
  
  
  
  return EventPublishPass;
}


EVENT_PUBLISH_STATUS HyperDbgMTFHandler(PEVENT_ARGUMENTS args)
{
  Bit32u bp_index;

  

  if(!hyperdbg_state.hasPermBP && !hyperdbg_state.singlestepping && !hyperdbg_state.selfmodifying_singlestepping && !hyperdbg_state.protection_singlestepping) {
    
    Log("Spurious MTF !!!");
    return EventPublishPass;
  }

  
  hvm_x86_ops.vt_switch_mtf(FALSE);

  if(hyperdbg_state.pfstepping == TRUE) {
    GodLog("[HyperDbgMTFHandler] EIP: %08hx", context.GuestContext.rip);
    __asm__ __volatile__("ud2\n");
  }

  if(hyperdbg_state.protection_singlestepping == TRUE) {

    
    HyperDbgCheckWrite();

    protected_phy_index = 0; 
    hyperdbg_state.protection_singlestepping = FALSE;
  }
  else if(hyperdbg_state.selfmodifying_singlestepping == TRUE) {
    GodLog("[HyperDbgMTFHandler] Step on self modifying code done, re-enabling EXEC protection");

    
    
    
		
    EPTRemovePTperms(selfmodifying_tobeprotected, EXEC);
    selfmodifying_tobeprotected = 0;

    hyperdbg_state.selfmodifying_singlestepping = FALSE;
  }

  if(hyperdbg_state.hasPermBP) {
    bp_index = SwBreakpointSet(hyperdbg_state.bp_cr3, hyperdbg_state.previous_codeaddr, TRUE, hyperdbg_state.isPermBPCr3Dipendent);
    hyperdbg_state.hasPermBP = FALSE;
    
    
  }

  if(hyperdbg_state.singlestepping) {
    HyperDbgEnter();
  }

  return EventPublishHandled;
}

EVENT_PUBLISH_STATUS HyperDbgIO(void)
{
  return EventPublishHandled;
}

hvm_status HyperDbgHostInit(void)
{
  EVENT_CONDITION_EXCEPTION exception;
  EVENT_CONDITION_IO io;
  EVENT_CONDITION_HYPERCALL hypercall;
#ifdef ENABLE_EPT
  EVENT_CONDITION_EPT_VIOLATION ept_violation;
#endif
  EVENT_CONDITION_CR cr;
  EVENT_CONDITION_NONE none;
  hvm_status r;

  
  r = KeyboardInit();
  if (r != HVM_STATUS_SUCCESS)
    return r;

  vmm_memset(protected_phy_pages, 0, MAX_PROTECTED_PHY * sizeof(PHY_PROTECTED));

  
  if(!EventSubscribe(EventMtf, &none, sizeof(none), HyperDbgMTFHandler)) {
    return HVM_STATUS_UNSUCCESSFUL;
  }

#ifdef ENABLE_EPT
  if(!EventSubscribe(EventEPTViolation, &ept_violation, sizeof(ept_violation), HyperDbgViolationHandler)) {
    return HVM_STATUS_UNSUCCESSFUL;
  }
#endif

  cr.crno = 3;
  cr.iswrite = TRUE;
  if(!EventSubscribe(EventControlRegister, &cr, sizeof(cr), HyperDbgCRHandler)) {
    return HVM_STATUS_UNSUCCESSFUL;
  }

  
  exception.exceptionnum = TRAP_INT3;
  if(!EventSubscribe(EventException, &exception, sizeof(exception), HyperDbgSwBpHandler)) {
    return HVM_STATUS_UNSUCCESSFUL;
  }

  
  hypercall.hypernum = HYPERDBG_HYPERCALL_USER;
  if(!EventSubscribe(EventHypercall, &hypercall, sizeof(hypercall), HyperDbgHypercallUser)) {
    GuestLog("ERROR: Unable to register non-root -> root hypercall handler");
    return HVM_STATUS_UNSUCCESSFUL;
  }

  hypercall.hypernum = HYPERDBG_HYPERCALL_TRACEME;
  if(!EventSubscribe(EventHypercall, &hypercall, sizeof(hypercall), HyperDbgHypercallTraceMe)) {
    GuestLog("ERROR: Unable to register non-root -> root hypercall handler");
    return HVM_STATUS_UNSUCCESSFUL;
  }

  hypercall.hypernum = HYPERDBG_HYPERCALL_FORGETME;
  if(!EventSubscribe(EventHypercall, &hypercall, sizeof(hypercall), HyperDbgHypercallForgetMe)) {
    GuestLog("ERROR: Unable to register non-root -> root hypercall handler");
    return HVM_STATUS_UNSUCCESSFUL;
  }

    hypercall.hypernum = HYPERDBG_HYPERCALL_VISITING;
  if(!EventSubscribe(EventHypercall, &hypercall, sizeof(hypercall), HyperDbgHypercallVisiting)) {
    GuestLog("ERROR: Unable to register non-root -> root hypercall handler");
    return HVM_STATUS_UNSUCCESSFUL;
  }

  
  io.direction = EventIODirectionIn;
  io.portnum = (Bit32u) KEYB_REGISTER_OUTPUT;
  if(!EventSubscribe(EventIO, &io, sizeof(io), HyperDbgIOHandler)) {
    return HVM_STATUS_UNSUCCESSFUL;
  }

  GodInit();

  return HVM_STATUS_SUCCESS;
}

hvm_status HyperDbgHostFini(void)
{
  EVENT_CONDITION_EXCEPTION exception;
    
  exception.exceptionnum = TRAP_INT3;
  EventUnsubscribe(EventException, &exception, sizeof(exception));
  return HVM_STATUS_SUCCESS;
}
