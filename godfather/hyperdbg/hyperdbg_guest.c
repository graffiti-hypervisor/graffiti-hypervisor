


#include "hyperdbg.h"
#include "hyperdbg_common.h"
#include "hyperdbg_guest.h"
#include "hyperdbg_host.h"

#ifdef GUEST_WINDOWS
#include "winxp.h"
#elif defined GUEST_LINUX

#endif

#include "keyboard.h"
#include "debug.h"
#include "vt.h"
#include "video.h"
#include "mmu.h"






HYPERDBG_STATE hyperdbg_state;






hvm_status HyperDbgGuestInit(void)
{
  hvm_status r;

  
  if(VideoInit() != HVM_STATUS_SUCCESS) {
    GuestLog("[HyperDbg] Video initialization error");
    return HVM_STATUS_UNSUCCESSFUL;
  }

  
  r = VideoAlloc();
  if(r != HVM_STATUS_SUCCESS) {
    GuestLog("[HyperDbg] Cannot initialize video!");
    return HVM_STATUS_UNSUCCESSFUL;
  }

  
  hyperdbg_state.initialized = TRUE;
  hyperdbg_state.enabled = FALSE;
  hyperdbg_state.singlestepping = FALSE;
  hyperdbg_state.protection_singlestepping = FALSE;
  hyperdbg_state.console_mode = TRUE;
  hyperdbg_state.hasPermBP = FALSE;
  hyperdbg_state.ntraps = 0;
  
  
#ifdef GUEST_WINDOWS
  r = WindowsGetKernelBase(&hyperdbg_state.win_state.kernel_base);
  if (r != HVM_STATUS_SUCCESS) {
    GuestLog("[HyperDbg] Cannot initialize guest-specific variables!");
    return HVM_STATUS_UNSUCCESSFUL;
  }
#elif defined GUEST_LINUX

#else
#error Invalid HyperDBG guest!
#endif

  GuestLog("[HyperDbg] Guest initialization ok!");

  return HVM_STATUS_SUCCESS;
}


hvm_status HyperDbgGuestFini(void)
{
  if(!hyperdbg_state.initialized) return HVM_STATUS_SUCCESS;

  GuestLog("[HyperDbg] Unloading...");

  
  VideoDealloc();

  hyperdbg_state.initialized = FALSE;

  return HVM_STATUS_SUCCESS;
}
