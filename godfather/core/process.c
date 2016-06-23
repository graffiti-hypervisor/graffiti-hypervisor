


#include "process.h"
#include "vmmstring.h"
#include "debug.h"

#ifdef GUEST_WINDOWS
#include "winxp.h"
#elif defined GUEST_LINUX
#include <linux/sched.h>
#include "linux.h"
#endif

hvm_status ProcessGetNextProcess(hvm_address cr3, PPROCESS_DATA pprev, PPROCESS_DATA pnext)
{
  hvm_status r;

#ifdef GUEST_WINDOWS
  r = WindowsGetNextProcess(cr3, pprev, pnext);
#elif defined GUEST_LINUX
  r = LinuxGetNextProcess(cr3, pprev, pnext);
#endif

  return r;
}

hvm_status ProcessGetNextModule(hvm_address cr3, PMODULE_DATA pprev, PMODULE_DATA pnext)
{
  hvm_status r;

#ifdef GUEST_WINDOWS
  r = WindowsGetNextModule(cr3, pprev, pnext);
#elif defined GUEST_LINUX
  
  r = HVM_STATUS_UNSUCCESSFUL;
#endif

  return r;
}

hvm_status ProcessGetNameByPid(hvm_address cr3, hvm_address pid, char *name)
{
  PROCESS_DATA prev, next;
  hvm_status r;

  vmm_memset(&next, 0, sizeof(next));

  r = ProcessGetNextProcess(cr3, NULL, &next);
  while(TRUE) {
    if(r == HVM_STATUS_END_OF_FILE)
      break;
    
    if(r != HVM_STATUS_UNSUCCESSFUL && pid == next.pid) {
#ifdef GUEST_WINDOWS      
      vmm_strncpy(name, next.name, 32);
#elif defined GUEST_LINUX
      vmm_strncpy(name, next.name, TASK_COMM_LEN);
#endif
      return HVM_STATUS_SUCCESS;
    }
    prev = next;
    vmm_memset(next.name, 0, sizeof(next.name));
    r = ProcessGetNextProcess(cr3, &prev, &next);
  }
  return HVM_STATUS_UNSUCCESSFUL;
}

hvm_status ProcessGetModuleByAddr(hvm_address cr3, hvm_address addr, char *name)
{
  MODULE_DATA prev, next;
  hvm_status r;
#ifdef GUEST_WINDOWS      
  vmm_memset(&next, 0, sizeof(next));
  vmm_memset(&prev, 0, sizeof(prev));

  r = ProcessGetNextModule(cr3, NULL, &next);
  while(TRUE) {
    if(r == HVM_STATUS_END_OF_FILE)
      break;
    
    if(r != HVM_STATUS_UNSUCCESSFUL && (addr < (hvm_address) ((Bit32u) next.baseaddr + next.sizeofimage) && addr >= next.baseaddr)) {
      vmm_strncpy(name, next.name, 32);
      return HVM_STATUS_SUCCESS;
    }
    prev = next;
    vmm_memset(next.name, 0, sizeof(next.name));
    r = ProcessGetNextModule(cr3, &prev, &next);
  }
  return HVM_STATUS_UNSUCCESSFUL;
#elif defined GUEST_LINUX
  
  r = HVM_STATUS_UNSUCCESSFUL;
#endif

}

hvm_status ProcessFindProcessPid(hvm_address cr3, hvm_address *pid)
{
  hvm_status r;
  
#ifdef GUEST_WINDOWS
  r = WindowsFindProcessPid(cr3, pid);
#else
  r = LinuxFindProcessPid(cr3, pid);
#endif
  
  return r;
}

hvm_status ProcessFindProcessTid(hvm_address cr3, hvm_address *tid)
{
  hvm_status r;
  
#ifdef GUEST_WINDOWS
  r = WindowsFindProcessTid(cr3, tid);
#else
  r = LinuxFindProcessTid(cr3, tid);
#endif
  
  return r;
}
