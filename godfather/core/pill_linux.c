


#include "pill.h"
#include <asm/io.h>
#include "linux.h"
#include <linux/module.h>
#include <linux/kobject.h>
module_init(DriverEntry);
module_exit(DriverUnload);

static hvm_bool    ScrubTheLaunch = FALSE;
static hvm_address GuestReturn;
static hvm_address HostCR3;





static hvm_status InitGuest(void);
static hvm_status FiniGuest(void);
static hvm_status InitPlugin(void);





void StartVT()
{
  
  
  
  
  
  
  
  

  GuestReturn = (hvm_address) __builtin_return_address(0);
  GuestLog("Guest Return EIP: %.8x", GuestReturn);
  GuestLog("Enabling VT mode");

  
  
  
  
  

  
  
  
  if (!HVM_SUCCESS(hvm_x86_ops.vt_hardware_enable())) {
    goto Abort;
  }
  
  
  
  
  
  
  
  if (!HVM_SUCCESS(hvm_x86_ops.vt_vmcs_initialize(GuestStack, GuestReturn, HostCR3)))
    goto Abort;
  
  
  if (!HVM_SUCCESS(hvm_x86_ops.hvm_update_events()))
    goto Abort;

  
  hvm_x86_ops.vt_launch();
  
  Log("VMLAUNCH Failure");
  
 Abort:
  ScrubTheLaunch = TRUE;

  __asm__ __volatile__ (
			"movl %0,%%esp\n"			
			"jmp  *%1\n"
			::"m"(GuestStack),"m"(GuestReturn)
			);
}


void __exit DriverUnload(void)
{
  ScrubTheLaunch = FALSE;
 
  GuestLog("[vmm-unload] Disabling VT mode");

  
  
  
  
  
  FiniPlugin();			
  FiniGuest();			
    
  if(hvm_x86_ops.vt_enabled()) {
    hvm_x86_ops.vt_hypercall(HYPERCALL_SWITCHOFF);
  }
  
  GuestLog("[vmm-unload] Freeing memory regions");
  
  hvm_x86_ops.vt_finalize();
  MmuFini();			       
  GuestLog("[vmm-unload] Driver unloaded");
}


int __init DriverEntry(void)
{ 
  CR4_REG cr4;

  
#ifdef DEBUG
    PortInit();
    ComInit();
#endif

  GuestLog("Driver Routines");
  GuestLog("---------------");
  GuestLog("   Driver Entry:  %.8x", (hvm_address) DriverEntry);
  GuestLog("   StartVT:       %.8x", (hvm_address) StartVT);
  GuestLog("   VMMEntryPoint: %.8x", (hvm_address) hvm_x86_ops.hvm_handle_exit);

  
  CR4_TO_ULONG(cr4) = RegGetCr4();

  
  if(cr4.PAE) {
    GuestLog("ERROR: No support for Linux PAE ATM...");
    goto error;
  }

  
  if (!HVM_SUCCESS(RegisterEvents())) {
    GuestLog("Failed to register events");
    goto error;
  }

  
  if (!HVM_SUCCESS(hvm_x86_ops.vt_initialize(InitVMMIDT))) {
    GuestLog("Failed to initialize VT");
    goto error;
  }

#ifdef ENABLE_HYPERDBG
  
  if(HyperDbgGuestInit() != HVM_STATUS_SUCCESS) {
    GuestLog("ERROR: HyperDbg GUEST initialization error");
    return HVM_STATUS_UNSUCCESSFUL;
  }
#endif
  
  
  if (!HVM_SUCCESS(MmuInit(&HostCR3))) {
    GuestLog("Failed to initialize MMU");
    goto error;
  }
  GuestLog("Using private CR3: %08x", HostCR3);
  
  
  if (!HVM_SUCCESS(InitGuest())) {
    GuestLog("Failed to initialize guest-specific stuff");
    goto error;
  }
   
  
  if (!HVM_SUCCESS(InitPlugin())) {
    GuestLog("Failed to initialize plugin");
    goto error;
  }

  if (!HVM_SUCCESS(LinuxInitStructures())) {
	GuestLog("Failed to initialize data structures");
	goto error;
  }

  DoStartVT();
  
  if(ScrubTheLaunch == TRUE){
    GuestLog("ERROR: Launch aborted");
    goto error;
  }
  
  GuestLog("VM is now executing");
  
  return STATUS_SUCCESS;
  
 error:
  
  
  FiniPlugin();
  
  hvm_x86_ops.vt_finalize();
  
  return STATUS_UNSUCCESSFUL;
}

static hvm_status InitPlugin(void)
{
#ifdef ENABLE_HYPERDBG
  
  if(HyperDbgHostInit() != HVM_STATUS_SUCCESS) {
    GuestLog("ERROR: HyperDbg HOST initialization error");
    return HVM_STATUS_UNSUCCESSFUL;
  }
#endif
  
  return HVM_STATUS_SUCCESS;
}

static hvm_status InitGuest(void)
{
  return HVM_STATUS_SUCCESS;
}

static hvm_status FiniGuest(void)
{
  return HVM_STATUS_SUCCESS;
}
