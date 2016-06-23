


#include "pill.h"
#include "winxp.h"

static hvm_bool    ScrubTheLaunch = FALSE;
static hvm_address GuestReturn;
static hvm_address HostCR3;





static hvm_status InitGuest(PDRIVER_OBJECT DriverObject);
static hvm_status FiniGuest(void);
static hvm_status InitPlugin(void);





static UNICODE_STRING kqap,kssat;
static UNICODE_STRING kgcpn; 
static t_KeQueryActiveProcessors KeQueryActiveProcessors;
static t_KeSetSystemAffinityThread KeSetSystemAffinityThread;
static t_KeGetCurrentProcessorNumber KeGetCurrentProcessorNumber; 





void StartVT()
{
  
  
  
  
  
  
  
  
  GuestReturn = (hvm_address) __builtin_return_address(0);
  
  GuestLog("Guest Return EIP: %.8x", GuestReturn);
  GuestLog("Enabling VT mode");
  
  
  KeSetSystemAffinityThread((KAFFINITY) 0x00000001);
  
  
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
			"movl %%ebp, %%esp\n"
			"popl %%ebp\n"
			"ret"
			::"m"(GuestStack),"m"(GuestReturn)
			);
}


VOID DDKAPI DriverUnload(PDRIVER_OBJECT DriverObject)
{
  GuestLog("[vmm-unload] Active processor bitmap: %.8x", (ULONG) KeQueryActiveProcessors());
  GuestLog("[vmm-unload] Disabling VT mode");

  KeSetSystemAffinityThread((KAFFINITY) 0x00000001);

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


NTSTATUS DDKAPI DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  CR4_REG cr4;

  ScrubTheLaunch= FALSE;

  
  RtlInitUnicodeString(&kqap, L"KeQueryActiveProcessors");
  RtlInitUnicodeString(&kssat, L"KeSetSystemAffinityThread");

  
  RtlInitUnicodeString(&kgcpn, L"KeGetCurrentProcessorNumber");
  KeQueryActiveProcessors = (t_KeQueryActiveProcessors) MmGetSystemRoutineAddress(&kqap);
  KeSetSystemAffinityThread = (t_KeSetSystemAffinityThread) MmGetSystemRoutineAddress(&kssat);

    
  KeGetCurrentProcessorNumber = (t_KeGetCurrentProcessorNumber) MmGetSystemRoutineAddress(&kgcpn);
  
  DriverObject->DriverUnload = (PDRIVER_UNLOAD) &DriverUnload;
  
  
  PortInit();
  ComInit();

  GuestLog("Driver Routines");
  GuestLog("---------------");
  GuestLog("   Driver Entry:  %.8x", DriverEntry);
  GuestLog("   Driver Unload: %.8x", DriverUnload);
  GuestLog("   StartVT:       %.8x", StartVT);
  GuestLog("   VMMEntryPoint: %.8x", hvm_x86_ops.hvm_handle_exit);
  
  
  CR4_TO_ULONG(cr4) = RegGetCr4();
  
#ifdef ENABLE_PAE
  if(!cr4.PAE) {
    GuestLog("PAE support enabled, but the guest is NOT using it ");
    GuestLog("Add the option /pae to boot.ini");
    goto error;
  }
#else
  if(cr4.PAE) {
    GuestLog("PAE support disabled, but the guest is using it ");
    GuestLog("Add the options /noexecute=alwaysoff /nopae to boot.ini");
    goto error;
  }
#endif

  
  if (!HVM_SUCCESS(RegisterEvents())) {
    GuestLog("Failed to register events");
    goto error;
  }
 
  
  if (!HVM_SUCCESS(hvm_x86_ops.vt_initialize(InitVMMIDT))) {
    GuestLog("Failed to initialize VT");
    goto error;
  }
 
  
  if (!HVM_SUCCESS(InitGuest(DriverObject))) {
    GuestLog("Failed to initialize guest-specific stuff");
    goto error;
  }
   
  
  if (!HVM_SUCCESS(InitPlugin())) {
    GuestLog("Failed to initialize plugin");
    goto error;
  }

  
  if (!HVM_SUCCESS(MmuInit(&HostCR3))) {
    GuestLog("Failed to initialize MMU");
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
  
  if(HyperDbgGuestInit() != HVM_STATUS_SUCCESS) {
    GuestLog("ERROR: HyperDbg GUEST initialization error");
    return HVM_STATUS_UNSUCCESSFUL;
  }

  
  if(HyperDbgHostInit() != HVM_STATUS_SUCCESS) {
    GuestLog("ERROR: HyperDbg HOST initialization error");
    return HVM_STATUS_UNSUCCESSFUL;
  }
#endif
  
  return HVM_STATUS_SUCCESS;
}

static hvm_status InitGuest(PDRIVER_OBJECT DriverObject)
{
  if (WindowsInit(DriverObject) != HVM_STATUS_SUCCESS) {
    GuestLog("ERROR: Windows-specific initialization routine has failed");
    return HVM_STATUS_UNSUCCESSFUL;
  }
  return HVM_STATUS_SUCCESS;
}

static hvm_status FiniGuest(void)
{
  return HVM_STATUS_SUCCESS;
}

