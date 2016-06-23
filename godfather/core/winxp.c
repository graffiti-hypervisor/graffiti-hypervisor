



#include "winxp.h"
#include "debug.h"
#include "mmu.h"
#include "common.h"
#include "vmmstring.h"
#include <ddk/ntddk.h>





#define SHAREDUSERDATA 0x7ffe0000
#define KUSER_SHARED_DATA_PHYPAGES_OFFSET 0x2e8
#define SystemModuleInformation 11





typedef NTSTATUS (NTAPI *NTQUERYSYSTEMINFORMATION)(ULONG, PVOID, ULONG, PULONG);

static struct {
  NTQUERYSYSTEMINFORMATION NtQuerySystemInformation;
  ULONG PsLoadedModuleList;
  PEPROCESS PsInitialSystemProcess;
} WindowsSymbols;

#ifdef GUEST_WIN_7
static hvm_status  Windows7FindNetworkConnections(hvm_address cr3, SOCKET *buf, Bit32u maxsize, Bit32u *psize);
static hvm_status  Windows7FindNetworkData(hvm_address cr3, SOCKET *buf, Bit32u maxsize, Bit32u *psize, unsigned int type);
#else
static hvm_status  WindowsFindNetworkConnections(hvm_address cr3, SOCKET *buf, Bit32u maxsize, Bit32u *psize);
static hvm_status  WindowsFindNetworkSockets(hvm_address cr3, SOCKET *buf, Bit32u maxsize, Bit32u *psize);
#endif
static hvm_address WindowsFindPsLoadedModuleList(PDRIVER_OBJECT DriverObject);

hvm_address fs;






hvm_status WindowsInit(PDRIVER_OBJECT DriverObject)
{
  UNICODE_STRING u;

  asm ( "movl %%fs:0x20, %0\n"
	: "=r" (fs)
        );

  Log("fs is 0x%x", fs);

  RtlInitUnicodeString(&u, L"NtQuerySystemInformation");
  WindowsSymbols.NtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION) MmGetSystemRoutineAddress(&u);  
  if (!WindowsSymbols.NtQuerySystemInformation) return HVM_STATUS_UNSUCCESSFUL;

  WindowsSymbols.PsLoadedModuleList = WindowsFindPsLoadedModuleList(DriverObject);
  if (WindowsSymbols.PsLoadedModuleList == 0) return HVM_STATUS_UNSUCCESSFUL;
  
  RtlInitUnicodeString(&u, L"PsInitialSystemProcess");
  WindowsSymbols.PsInitialSystemProcess= (PEPROCESS) *((PEPROCESS*) MmGetSystemRoutineAddress(&u));
  if (WindowsSymbols.PsInitialSystemProcess == 0) return HVM_STATUS_UNSUCCESSFUL;
  
  return HVM_STATUS_SUCCESS;
}

hvm_address WindowsGetPTIB()
{
  return fs;
}

static hvm_address WindowsFindPsLoadedModuleList(PDRIVER_OBJECT DriverObject)
{
  hvm_address v;

  v = 0;

  if (!DriverObject) return 0;

  v = *(hvm_address*) ((hvm_address) DriverObject + FIELD_OFFSET(DRIVER_OBJECT, DriverSection));

  return v;
}

hvm_status WindowsGetKeyboardVector(unsigned char* pv)
{
  NTSTATUS       r;
  PDEVICE_OBJECT pDeviceObject;
  PFILE_OBJECT   pFileObject;
  UNICODE_STRING us;
  PKINTERRUPT    pKInterrupt;

  pDeviceObject = NULL;
  pKInterrupt   = NULL;
  
  RtlInitUnicodeString(&us, L"\\Device\\KeyboardClass0");

  
  r = IoGetDeviceObjectPointer(&us, FILE_READ_ATTRIBUTES, &pFileObject, &pDeviceObject);

  if(r != STATUS_SUCCESS)
    return HVM_STATUS_UNSUCCESSFUL;

  while(pDeviceObject->DeviceType != FILE_DEVICE_8042_PORT) {
    PR_DEVOBJ_EXTENSION pde;

    
    pde = (PR_DEVOBJ_EXTENSION) pDeviceObject->DeviceObjectExtension;
    if (pde->AttachedTo)
      pDeviceObject = pde->AttachedTo;
    else 
      return HVM_STATUS_UNSUCCESSFUL;
  }

  
  pKInterrupt = (PKINTERRUPT) ((PPORT_KEYBOARD_EXTENSION) pDeviceObject->DeviceExtension)->InterruptObject;

  *pv = (unsigned char) (pKInterrupt->Vector & 0xff);

  return HVM_STATUS_SUCCESS;
}


hvm_status WindowsGetKernelBase(hvm_address* pbase)
{
  Bit32u i, Byte, ModuleCount;
  hvm_address* pBuffer;
  PSYSTEM_MODULE_INFORMATION pSystemModuleInformation;
  hvm_status r;
  WindowsSymbols.NtQuerySystemInformation(SystemModuleInformation, (PVOID) &Byte, 0, (PULONG) &Byte);
  pBuffer = MmAllocateNonCachedMemory(Byte);          
  if(!pBuffer)
    return HVM_STATUS_UNSUCCESSFUL;
  if(WindowsSymbols.NtQuerySystemInformation(SystemModuleInformation, pBuffer, Byte, (PULONG) &Byte)) {
    MmFreeNonCachedMemory(pBuffer, Byte);
    return HVM_STATUS_UNSUCCESSFUL;
  }

  ModuleCount = *(hvm_address*) pBuffer;
  pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)((unsigned char*) pBuffer + sizeof(Bit32u));
  r = HVM_STATUS_UNSUCCESSFUL;
  for(i = 0; i < ModuleCount; i++) {
    if(strstr(pSystemModuleInformation->ImageName, "ntoskrnl.exe") ||
       strstr(pSystemModuleInformation->ImageName, "ntkrnlpa.exe")) {
      r = HVM_STATUS_SUCCESS;
      *pbase = (hvm_address) pSystemModuleInformation->Base;
      break;
    }
    pSystemModuleInformation++;
  }
                
  MmFreeNonCachedMemory(pBuffer, Byte);

  return r;
}

hvm_status  WindowsFindModuleByName(hvm_address cr3, Bit8u *name, MODULE_DATA *pmodule)
{
  MODULE_DATA prev, next;
  hvm_status r;

  r = ProcessGetNextModule(cr3, NULL, &next);

  while (1) {
    if (r == HVM_STATUS_END_OF_FILE) {
      
      break;
    } else if (r != HVM_STATUS_SUCCESS) {
      
      Log("[Win] Can't read traverse modules list");
      break;
    }

    if (!vmm_strncmpi(name, next.name, vmm_strlen(name))) {
      vmm_memcpy(pmodule, &next, sizeof(next));
      return HVM_STATUS_SUCCESS; 
    }

    
    prev = next;
    r = ProcessGetNextModule(cr3, &prev, &next);
  }

  
  return HVM_STATUS_UNSUCCESSFUL;
}

hvm_status WindowsFindModule(hvm_address cr3, hvm_address addr, char *name)
{
  hvm_status  r;
  hvm_address proc, v, pldr;
  ULONG       module_current, module_head;
  LIST_ENTRY le;
  PEB_LDR_DATA ldr;
  LDR_MODULE module;
  Bit16u wname[64];

  
  r = WindowsFindProcess(cr3, &proc);

  if (r != HVM_STATUS_SUCCESS)
    return r;

  
  r = MmuReadVirtualRegion(cr3, proc + OFFSET_EPROCESS_PEB, &v, sizeof(v));
  if (r != HVM_STATUS_SUCCESS ) {
    ComPrint("[HyperDbg] Can't read PEB at offset %.8x\n", proc + OFFSET_EPROCESS_PEB);
    return r;
  }

  if (v == 0) {
    
    module_current = module_head = WindowsSymbols.PsLoadedModuleList;
  } else {
    
    r = MmuReadVirtualRegion(cr3, v + OFFSET_PEB_LDRDATA, &pldr, sizeof(pldr));
    if (r != HVM_STATUS_SUCCESS ) {
      ComPrint("[HyperDbg] Can't read PPEB_LDR_DATA at offset %.8x\n", v + OFFSET_PEB_LDRDATA);
      return r;
    }

    r = MmuReadVirtualRegion(cr3, pldr, &ldr, sizeof(ldr));
    if (r != HVM_STATUS_SUCCESS ) {
      ComPrint("[HyperDbg] Can't read PEB_LDR_DATA at offset %.8x\n", pldr);
      return r;
    }

    module_current = module_head = (ULONG) ldr.InLoadOrderModuleList.Flink;
  }

  
  do {
    r = MmuReadVirtualRegion(cr3, (hvm_address) module_current - FIELD_OFFSET(LDR_MODULE, InLoadOrderModuleList), &module, sizeof(module));
    if (r != HVM_STATUS_SUCCESS ) break;

    if (addr < (ULONG) module.BaseAddress + (ULONG)module.SizeOfImage && addr >= (ULONG)module.BaseAddress) {

      r = MmuReadVirtualRegion(cr3, (hvm_address) module.BaseDllName.Buffer, wname, MIN(module.BaseDllName.MaximumLength, sizeof(wname)/sizeof(Bit16u)));

      if (r != HVM_STATUS_SUCCESS) {
	name[0] = '\0';
      } else {
	wide2ansi(name, (Bit8u*) wname, MIN(module.BaseDllName.MaximumLength, sizeof(wname)/sizeof(Bit16u)));
      }
      return HVM_STATUS_SUCCESS; 
    }

    module_current = (ULONG) module.InLoadOrderModuleList.Flink;
  } while (module_current != module_head);

  
  
  
  return HVM_STATUS_UNSUCCESSFUL;
}

Bit32u WindowsGuessFrames(void)
{
  Bit32u dwPhyPages;

  dwPhyPages = *(Bit32u*) (SHAREDUSERDATA + KUSER_SHARED_DATA_PHYPAGES_OFFSET);

  return dwPhyPages;
}

hvm_bool WindowsProcessIsTerminating(hvm_address cr3)
{
  hvm_address pep;
  Bit32u flags;
  hvm_bool b;
  hvm_status r;

  r = WindowsFindProcess(cr3, &pep);
  
  b = TRUE;

  if (r == HVM_STATUS_SUCCESS) {
    
    r = MmuReadVirtualRegion(cr3, pep + OFFSET_EPROCESS_FLAGS, &flags, sizeof(flags));
    if (r == HVM_STATUS_SUCCESS && (flags & EPROCESS_FLAGS_DELETE) == 0) {
      
      b = FALSE;
    }
  }

  return b;
}


hvm_status WindowsFindProcess(hvm_address cr3, hvm_address* ppep)
{
  PROCESS_DATA prev, next;
  hvm_status r;
  hvm_bool found;

  
  found = FALSE;
  r = ProcessGetNextProcess(context.GuestContext.cr3, NULL, &next);

  while (1) {
    if (r == HVM_STATUS_END_OF_FILE) {
      
      break;
    } else if (r != HVM_STATUS_SUCCESS) {
      Log("[Win] Can't read next process. Current process: %.8x", next.pobj);
      break;
    }

    if (next.cr3 == cr3) {
      
      found = TRUE;
      *ppep = next.pobj;
      break;
    }

    
    prev = next;
    r = ProcessGetNextProcess(context.GuestContext.cr3, &prev, &next);
  }

  return found ? HVM_STATUS_SUCCESS : HVM_STATUS_UNSUCCESSFUL;
}

hvm_status WindowsFindProcessPid(hvm_address cr3, hvm_address* ppid)
{
  hvm_address pep;
  hvm_status r;

  r = WindowsFindProcess(cr3, &pep);
  if (r != HVM_STATUS_SUCCESS) return r;

  r = MmuReadVirtualRegion(cr3, pep + OFFSET_EPROCESS_UNIQUEPID, ppid, sizeof(hvm_address));
  if (r != HVM_STATUS_SUCCESS) return r;

  return HVM_STATUS_SUCCESS;
}

hvm_status WindowsFindProcessName(hvm_address cr3, char* name)
{
  hvm_address pep;
  hvm_status r;

  r = WindowsFindProcess(cr3, &pep);
  if (r != HVM_STATUS_SUCCESS) return r;

  r = MmuReadVirtualRegion(cr3, pep + OFFSET_EPROCESS_IMAGEFILENAME, name, 16);
  if (r != HVM_STATUS_SUCCESS) return r;

  return HVM_STATUS_SUCCESS;
}

hvm_status WindowsFindProcessTid(hvm_address cr3, hvm_address* ptid)
{
  hvm_address pep, kthread_current, kthread_head;
  hvm_status  r;
  hvm_bool    found;
  LIST_ENTRY  le;
  Bit8u       c;

  r = WindowsFindProcess(cr3, &pep);
  if (r != HVM_STATUS_SUCCESS) return r;

  

  
  r = MmuReadVirtualRegion(cr3, pep + OFFSET_KPROCESS_THREADLISTHEAD, &kthread_head, sizeof(kthread_head));
  if (r != HVM_STATUS_SUCCESS) return r;

  kthread_head = kthread_head - OFFSET_KTHREAD_THREADLISTENTRY;

  kthread_current = kthread_head;
  found = FALSE;

  do {
    
    r = MmuReadVirtualRegion(cr3, kthread_current + OFFSET_KTHREAD_STATE, &c, sizeof(c));
    if (r == HVM_STATUS_SUCCESS && c == KTHREAD_STATE_RUNNING) {
      
      found = TRUE;
      break;
    }

    
    r = MmuReadVirtualRegion(cr3, kthread_current + OFFSET_KTHREAD_THREADLISTENTRY, &le, sizeof(le));
    if (r != HVM_STATUS_SUCCESS) {
      Log("[Win] Can't read LIST_ENTRY at offset %.8x, base %.8x", kthread_current + OFFSET_KTHREAD_THREADLISTENTRY, kthread_current);
      break;
    }

    kthread_current = (hvm_address) (le.Flink) - OFFSET_KTHREAD_THREADLISTENTRY;
  } while (kthread_current != kthread_head);

  if (found) {
    
    CLIENT_ID cid;

    r = MmuReadVirtualRegion(cr3, kthread_current + OFFSET_ETHREAD_CID, &cid, sizeof(cid));
    if (r != HVM_STATUS_SUCCESS) return r;

    *ptid = (hvm_address) cid.UniqueThread;
  }

  return found ? HVM_STATUS_SUCCESS : HVM_STATUS_UNSUCCESSFUL;
}

hvm_status WindowsGetNextProcess(hvm_address cr3, PPROCESS_DATA pprev, PPROCESS_DATA pnext)
{
  hvm_status r;
  
  if (!pnext) return HVM_STATUS_UNSUCCESSFUL;

  if (!pprev) {
    
    pnext->pobj = (hvm_address) WindowsSymbols.PsInitialSystemProcess;
  } else {
    
    LIST_ENTRY   le;
    
    if (!pprev->pobj) return HVM_STATUS_UNSUCCESSFUL;

    r = MmuReadVirtualRegion(cr3, pprev->pobj + OFFSET_EPROCESS_ACTIVELINKS, &le, sizeof(le));
    if (r != HVM_STATUS_SUCCESS) {
      Log("[Win] Can't read LIST_ENTRY at offset %.8x", pprev->pobj + OFFSET_EPROCESS_ACTIVELINKS);
      return HVM_STATUS_UNSUCCESSFUL;
    }

    pnext->pobj = (hvm_address) (le.Flink) - OFFSET_EPROCESS_ACTIVELINKS;

    if (pnext->pobj == (hvm_address) WindowsSymbols.PsInitialSystemProcess)
      return HVM_STATUS_END_OF_FILE;
  }

  
  r = MmuReadVirtualRegion(cr3, pnext->pobj + FIELD_OFFSET(KPROCESS, DirectoryTableBase), &(pnext->cr3), sizeof(pnext->cr3));
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

  
  r = MmuReadVirtualRegion(cr3, pnext->pobj + OFFSET_EPROCESS_UNIQUEPID, &(pnext->pid), sizeof(pnext->pid));
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

  
  r = MmuReadVirtualRegion(cr3, pnext->pobj + OFFSET_EPROCESS_IMAGEFILENAME, pnext->name, 16);
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

  return HVM_STATUS_SUCCESS;
}

hvm_status WindowsGetNextModule(hvm_address cr3, PMODULE_DATA pprev, PMODULE_DATA pnext)
{
  hvm_status r;
  LDR_MODULE module;
  Bit16u wname[64];

  if (!pnext) return HVM_STATUS_UNSUCCESSFUL;

  if (!pprev) {
    
    pnext->pobj = (hvm_address) WindowsSymbols.PsLoadedModuleList - FIELD_OFFSET(LDR_MODULE, InLoadOrderModuleList);
  } else {
    
    if (!pprev->pobj) return HVM_STATUS_UNSUCCESSFUL;

    r = MmuReadVirtualRegion(cr3, (hvm_address) pprev->pobj, &module, sizeof(module));
    if (r != HVM_STATUS_SUCCESS ) return HVM_STATUS_UNSUCCESSFUL;

    pnext->pobj = (hvm_address) module.InLoadOrderModuleList.Flink - FIELD_OFFSET(LDR_MODULE, InLoadOrderModuleList);

    if (pnext->pobj == (hvm_address) WindowsSymbols.PsLoadedModuleList - FIELD_OFFSET(LDR_MODULE, InLoadOrderModuleList))
      return HVM_STATUS_END_OF_FILE;
  }

  pnext->baseaddr    = (hvm_address) module.BaseAddress;
  pnext->entrypoint  = (hvm_address) module.EntryPoint;
  pnext->sizeofimage = (Bit32u) module.SizeOfImage;

  r = MmuReadVirtualRegion(cr3, (hvm_address) module.BaseDllName.Buffer, wname, MIN(module.BaseDllName.MaximumLength, sizeof(wname)/sizeof(Bit16u)));

  if (r != HVM_STATUS_SUCCESS) {
    pnext->name[0] = '\0';
  } else {
    vmm_memset(pnext->name, 0, sizeof(pnext->name));
    wide2ansi(pnext->name, (Bit8u*) wname, MIN(module.BaseDllName.MaximumLength, sizeof(wname)/sizeof(Bit16u))/2);
  }

  return HVM_STATUS_SUCCESS;
}


#ifdef GUEST_WIN_7
hvm_status Windows7FindTargetInfo(hvm_address cr3, hvm_address *target_pep, hvm_address *target_kthread) {

  hvm_status r;
  hvm_address kthread_head, kthread_current, thread_pep, pid;
  char process_name[32];
  LIST_ENTRY le;
  Bit8u thread_state;

  WindowsFindProcess(cr3, target_pep);
    
  
  r = MmuReadVirtualRegion(cr3, (*target_pep) + OFFSET_KPROCESS_THREADLISTHEAD, &kthread_head, sizeof(kthread_head));
  if(r != HVM_STATUS_SUCCESS) {

    Log("[Win] Can't read ThreadListHead of EPROCESS 0x%08hx, fail on va 0x%08hx", *target_pep, (*target_pep) + OFFSET_KPROCESS_THREADLISTHEAD);
    return r;
  }
  kthread_head = kthread_current = kthread_head - OFFSET_KTHREAD_THREADLISTENTRY;

  Log("[Win] KTHREAD head is at va 0x%08hx", kthread_head);
  
  do {

    MmuReadVirtualRegion(cr3, kthread_current + OFFSET_KTHREAD_PROCESS, &thread_pep, sizeof(hvm_address));
    MmuReadVirtualRegion(cr3, kthread_current + OFFSET_KTHREAD_THREADLISTENTRY, &le, sizeof(le));

    if(thread_pep == (*target_pep)) {

      Log("[Win] KTHREAD 0x%08hx", kthread_current);

      *target_kthread = kthread_current;

      vmm_memset(process_name, 0, sizeof(process_name));
      r = MmuReadVirtualRegion(cr3, thread_pep + OFFSET_EPROCESS_IMAGEFILENAME, &process_name, sizeof(process_name));
      if(r != HVM_STATUS_SUCCESS) vmm_strncpy(process_name, "UNKNOWN", 7);
      Log("[Win] ----> PEPROCESS:   0x%08hx/%s", thread_pep, process_name);
      MmuReadVirtualRegion(cr3, thread_pep + OFFSET_EPROCESS_UNIQUEPID, &pid, sizeof(pid));
      MmuReadVirtualRegion(cr3, kthread_current + OFFSET_KTHREAD_STATE, &thread_state, sizeof(thread_state));
      Log("[Win] ----> Process PID: 0x%x", pid);
      Log("[Win] ----> Flink:       0x%08hx", le.Flink);
      Log("[Win] ----> Blink:       0x%08hx", le.Blink);
      Log("[Win] ----> State:       %d", thread_state);
    }
    kthread_current = (hvm_address)le.Flink - OFFSET_KTHREAD_THREADLISTENTRY;
  } while(kthread_current != kthread_head);

  Log("[Win] Finish visit of process's ThreadList.");

  return HVM_STATUS_SUCCESS;
}

hvm_status Windows7UnlinkProc(hvm_address cr3, hvm_address target_pep, hvm_address target_kthread, unsigned int *dispatcher_index, Bit8u *success)
{
  hvm_address thread_pep, kthread_current, kthread_head, kthread_running, kthread_next;
  hvm_address kprcb, ready_list_entry;
  hvm_address pid;
  hvm_status  r;
  LIST_ENTRY  le, dispatcher_ready_array[32];
  SINGLE_LIST_ENTRY sle;
  char process_name[32], bitmap_binary_str[33];
  Bit8u thread_state;
  Bit32u ready_summary;
  unsigned int j;

  
  
  
  

  

  if(context.GuestContext.rax == target_kthread){
      
    Log("[Win] Denied running of target process!!! Switch to idle.");

    context.GuestContext.rax = 0;

    *dispatcher_index = context.GuestContext.rdi;

    *success = 1;
      
    
    __asm__ __volatile__ (

			  "push %%eax\n"
			  "mov %%fs:0x20, %%eax\n"
			  "mov %%eax, %0\n"
			  "pop %%eax\n"
			  :"=m"(kprcb)
			  ::"memory"
			  );

    r = MmuReadVirtualRegion(cr3, kprcb + OFFSET_PRCB_DISPATCHER_READY, &dispatcher_ready_array, sizeof(dispatcher_ready_array));
    if (r != HVM_STATUS_SUCCESS) {
      Log("[Win] Can't read LIST_ENTRY array at offset %.8x, base %.8x", kprcb + OFFSET_PRCB_DISPATCHER_READY, kprcb);
      return r;
    }

    r = MmuReadVirtualRegion(cr3, kprcb + OFFSET_PRCB_READYSUMMARY, &ready_summary, sizeof(ready_summary));
    if (r != HVM_STATUS_SUCCESS) {
      Log("[Win] Can't read ready_summary bitmap at va %08hx", kprcb + OFFSET_PRCB_READYSUMMARY);
      return r;
    }

    r = MmuReadVirtualRegion(cr3, kprcb + OFFSET_PRCB_CURRENT_THREAD, &kthread_running, sizeof(kthread_running));
    if (r != HVM_STATUS_SUCCESS) {
      Log("[Win] Can't read current thread ptr from va 0x%08hx...", kprcb + OFFSET_PRCB_CURRENT_THREAD);
      return r;
    }

    r = MmuReadVirtualRegion(cr3, kprcb + OFFSET_PRCB_NEXT_THREAD, &kthread_next, sizeof(kthread_next));
    if (r != HVM_STATUS_SUCCESS) {
      Log("[Win] Can't read next thread ptr from va 0x%08hx...", kprcb + OFFSET_PRCB_NEXT_THREAD);
      return r;
    }
  }

  return HVM_STATUS_SUCCESS;
}

hvm_status Windows7RelinkProc(hvm_address cr3, hvm_address target_kthread, unsigned int dispatcher_index)
{
  hvm_status r;
  hvm_address kprcb;
  LIST_ENTRY dispatcher_entry;
  hvm_address buffer;

  hvm_address thread_pep, kthread_current, kthread_head;
  hvm_address ready_list_entry;
  hvm_address pid;
  LIST_ENTRY  le, dispatcher_ready_array[32];
  char process_name[32];
  Bit8u thread_state;
  unsigned int j;

  
  __asm__ __volatile__ (

			"push %%eax\n"
			"mov %%fs:0x20, %%eax\n"
			"mov %%eax, %0\n"
			"pop %%eax\n"
			:"=m"(kprcb)
			::"memory"
			);

  r = MmuReadVirtualRegion(cr3, kprcb + OFFSET_PRCB_DISPATCHER_READY + dispatcher_index*sizeof(LIST_ENTRY), &dispatcher_entry, sizeof(dispatcher_entry));
  if (r != HVM_STATUS_SUCCESS) {
    Log("[Win] Can't read LIST_ENTRY (ready dispatcher entry) at va 0x%08hx (0x%08hx+0x%08hx*%0d)", kprcb + OFFSET_PRCB_DISPATCHER_READY + dispatcher_index*sizeof(LIST_ENTRY), kprcb + OFFSET_PRCB_DISPATCHER_READY, dispatcher_index, sizeof(LIST_ENTRY));
    return r;
  }

  buffer = target_kthread + OFFSET_KTHREAD_WAITLISTENTRY;
  
  kthread_head = (hvm_address)dispatcher_entry.Flink - OFFSET_KTHREAD_WAITLISTENTRY;
  kthread_current = kthread_head;
  do {
    r = MmuReadVirtualRegion(cr3, kthread_current + OFFSET_KTHREAD_WAITLISTENTRY, &le, sizeof(le));
    if (r != HVM_STATUS_SUCCESS) {
      Log("[Win] Can't read LIST_ENTRY at offset %.8x, base %.8x", kthread_current + OFFSET_KTHREAD_WAITLISTENTRY, kthread_current);
      return r;
    }

    if((hvm_address)(le.Flink) - OFFSET_KTHREAD_WAITLISTENTRY == kthread_head)
      MmuWriteVirtualRegion(cr3, kthread_current + OFFSET_KTHREAD_WAITLISTENTRY, &buffer, sizeof(hvm_address));

    kthread_current = (hvm_address)(le.Flink) - OFFSET_KTHREAD_WAITLISTENTRY;

  }while(kthread_current != kthread_head);

  

  
  buffer = target_kthread + OFFSET_KTHREAD_WAITLISTENTRY;
  r = MmuWriteVirtualRegion(cr3, (hvm_address)dispatcher_entry.Flink + sizeof(hvm_address), &buffer, sizeof(hvm_address));
  if (r != HVM_STATUS_SUCCESS) {
    return HVM_STATUS_UNSUCCESSFUL;
  }

  
  r = MmuWriteVirtualRegion(cr3, kprcb + OFFSET_PRCB_DISPATCHER_READY + dispatcher_index*sizeof(LIST_ENTRY), &buffer, sizeof(hvm_address));
  if (r != HVM_STATUS_SUCCESS) {
    return HVM_STATUS_UNSUCCESSFUL;
  }

  
  buffer = (hvm_address)dispatcher_entry.Flink;
  r = MmuWriteVirtualRegion(cr3, target_kthread + OFFSET_KTHREAD_WAITLISTENTRY, &buffer, sizeof(hvm_address));
  if (r != HVM_STATUS_SUCCESS) {
    return HVM_STATUS_UNSUCCESSFUL;
  }

  
  buffer = kprcb + OFFSET_PRCB_DISPATCHER_READY + dispatcher_index*sizeof(LIST_ENTRY);
  r = MmuWriteVirtualRegion(cr3, target_kthread + OFFSET_KTHREAD_WAITLISTENTRY + sizeof(hvm_address), &buffer, sizeof(hvm_address));
  if (r != HVM_STATUS_SUCCESS) {
    return HVM_STATUS_UNSUCCESSFUL;
  }

  return HVM_STATUS_SUCCESS;
}

hvm_status Windows7FindNetworkConnections(hvm_address cr3, SOCKET* buf, Bit32u maxsize, Bit32u *psize) {

  hvm_status r;
  hvm_address partition_table, partition_entry_array, partition_entry, tmp;
  hvm_address phash, pipinfo, peprocess, pipaddresses;
  Bit32u i, j, k, h, npart, nmaxhash, hash_index, tcp_conn_found = 0;
  Bit32u local_ip, remote_ip, pid, ports, ipv6;
  Bit16u local_port, remote_port, local_ipv6[8], remote_ipv6[8];
  MODULE_DATA tcp_module;

  r = WindowsFindModuleByName(cr3, "tcpip.sys", &tcp_module);
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

  
  r = MmuReadVirtualRegion(cr3, tcp_module.baseaddr + OFFSET_PARTITION_COUNTER, &npart, sizeof(npart));
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

  
  r = MmuReadVirtualRegion(cr3, tcp_module.baseaddr + OFFSET_PARTITION_TABLE, &partition_entry_array, sizeof(hvm_address));
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;
 
  
  for(j = 0; j < npart; j++) {

    
    r = MmuReadVirtualRegion(cr3, partition_entry_array + 0x48*j + sizeof(hvm_address), &partition_entry, sizeof(hvm_address));
    if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

    r = MmuReadVirtualRegion(cr3, partition_entry + OFFSET_PART_ENTRY_HASHTABLE, &phash, sizeof(hvm_address));
    if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

    r = MmuReadVirtualRegion(cr3, partition_entry + OFFSET_PART_ENTRY_MAXNUM, &nmaxhash, sizeof(nmaxhash));
    if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

    
    for(hash_index = 0; hash_index < nmaxhash; hash_index++) {

      r = MmuReadVirtualRegion(cr3, phash + hash_index * (2*sizeof(hvm_address)), &pipinfo, sizeof(hvm_address));
      if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;
	  
      
      while(pipinfo && pipinfo != phash+hash_index*(2*sizeof(hvm_address))) {

	

	r = MmuReadVirtualRegion(cr3, pipinfo + OFFSET_IPINFO_PEPROCESS, &peprocess, sizeof(hvm_address));
	if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

	r = MmuReadVirtualRegion(cr3, peprocess + OFFSET_EPROCESS_UNIQUEPID, &pid, sizeof(pid));
	if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

	r = MmuReadVirtualRegion(cr3, pipinfo + OFFSET_IPINFO_PORTS, &ports, sizeof(ports));
	if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

	remote_port = (ports & 0xffff0000) >> 16;
	local_port = ports & 0x0000ffff;

	r = MmuReadVirtualRegion(cr3, pipinfo + OFFSET_IPv6_1, &tmp, sizeof(hvm_address));
	if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

	r = MmuReadVirtualRegion(cr3, tmp + OFFSET_IPv6_2, &ipv6, sizeof(ipv6));
	if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

	if(ipv6 != 0x17) ipv6 = 0;
	else Log("[HyperDbg] Ipv6 connection at pipinfo 0x%08hx!!!", pipinfo); 

	r = MmuReadVirtualRegion(cr3, pipinfo + OFFSET_IPINFO_IPADDRESSES, &pipaddresses, sizeof(hvm_address));
	if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

	r = MmuReadVirtualRegion(cr3, pipaddresses + OFFSET_REMOTE_IP, &tmp, sizeof(hvm_address));
	if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

	if(ipv6) {

	  for(k = 0, h = 0; k < 0xe; k+=2, h++) {
	    r = MmuReadVirtualRegion(cr3, tmp + k, &remote_ipv6[h], sizeof(remote_ipv6[0]));
	    if(r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;
	  }
	}
	else {

	  r = MmuReadVirtualRegion(cr3, tmp, &remote_ip, sizeof(remote_ip));
	  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;
	}

	r = MmuReadVirtualRegion(cr3, pipaddresses, &pipaddresses, sizeof(hvm_address));
	if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

	if(ipv6) {

	  for(k = 0, h = 0; k < 0xe; k+=2, h++) {
	    r = MmuReadVirtualRegion(cr3, pipaddresses + OFFSET_LOCAL_IP + k, &local_ipv6[h], sizeof(remote_ipv6[0]));
	    if(r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;
	  }
	}
	else {
	  r = MmuReadVirtualRegion(cr3, pipaddresses + OFFSET_LOCAL_IP, &local_ip, sizeof(local_ip));
	  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;
	}
	if(tcp_conn_found < maxsize) {
	      
	  vmm_memset(&buf[tcp_conn_found], 0, sizeof(SOCKET));
	  buf[tcp_conn_found].state       = SocketStateEstablished;
	  buf[tcp_conn_found].local_port  = vmm_ntohs(local_port);
	  buf[tcp_conn_found].remote_port = vmm_ntohs(remote_port);
	  buf[tcp_conn_found].pid         = pid;
	  buf[tcp_conn_found].protocol    = 6; 

	  if(ipv6) {

	    for(k = 0; k < 8; k++)
	      buf[tcp_conn_found].local_ipv6[k] = local_ipv6[k];

	    for(k = 0; k < 8; k++)
	      buf[tcp_conn_found].remote_ipv6[k] = remote_ipv6[k];

	    buf[tcp_conn_found].local_ip = -1;
	    buf[tcp_conn_found].remote_ip = -1;	    
	  }
	  else {
	    buf[tcp_conn_found].local_ip  = local_ip;
	    buf[tcp_conn_found].remote_ip = remote_ip;
	  }

	  tcp_conn_found++;
	}
	
	r = MmuReadVirtualRegion(cr3, pipinfo, &pipinfo, sizeof(hvm_address));
	if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;
      }
    }
  }

  *psize = tcp_conn_found;

  Log("[HyperDbg] Search of TCP connections finished. Found: %d", tcp_conn_found);

  return HVM_STATUS_SUCCESS;
}

hvm_status Windows7FindNetworkData(hvm_address cr3, SOCKET* buf, Bit32u maxsize, Bit32u *psize, unsigned int type) {

  hvm_status r;
  hvm_address tmp, port_pool, pbitmap, pipinfo, peprocess;
  unsigned int i, j, k, h, skip, bitmap_size, page_number, page_offset, data_found = 0;
  Bit32u local_ip, pid;
  Bit16u local_port, remote_port, local_ipv6[8];
  Bit8u  bitmap_byte, ipv6;
  MODULE_DATA tcp_module;

  r = WindowsFindModuleByName(cr3, "tcpip.sys", &tcp_module);
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

  if(type == UDP) r = MmuReadVirtualRegion(cr3, tcp_module.baseaddr + OFFSET_UDP_PORT_POOL_PTR, &port_pool, sizeof(hvm_address));
  else r = MmuReadVirtualRegion(cr3, tcp_module.baseaddr + OFFSET_TCP_PORT_POOL_PTR, &port_pool, sizeof(hvm_address));
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

  r = MmuReadVirtualRegion(cr3, port_pool + OFFSET_BITMAP_PTR, &pbitmap, sizeof(hvm_address));
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

  r = MmuReadVirtualRegion(cr3, port_pool + OFFSET_BITMAP_SIZE, &bitmap_size, sizeof(bitmap_size));
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

  skip = 1; 
  
  bitmap_size /= 8;
  for(i = 0; i < bitmap_size; i++) {

    r = MmuReadVirtualRegion(cr3, pbitmap + i, &bitmap_byte, sizeof(bitmap_byte));
    if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;
    
    for(j = skip; j < 8; j++) {

      if((bitmap_byte >> j) & 0x01) {
      
	page_number = ((i*8+j) >> 8) & 0x00ff;
	page_offset =     (i*8+j)    & 0x00ff;

	r = MmuReadVirtualRegion(cr3, port_pool + OFFSET_PAGES_ARRAY + page_number * sizeof(hvm_address), &pipinfo, sizeof(hvm_address));
	if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

	r = MmuReadVirtualRegion(cr3, pipinfo + 0x14, &pipinfo, sizeof(hvm_address));
	if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

	r = MmuReadVirtualRegion(cr3, (pipinfo + (page_offset << 0x03) + 0x04), &pipinfo, sizeof(hvm_address));
	if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

	while(pipinfo) {

	  
	  pipinfo &= 0xfffffffc;

	  if(type == UDP) r = MmuReadVirtualRegion(cr3, pipinfo + OFFSET_UDP_LOCAL_PORT, &local_port, sizeof(local_port));
	  else r = MmuReadVirtualRegion(cr3, pipinfo + OFFSET_SOCKET_LOCAL_PORT, &local_port, sizeof(local_port));
	  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

	  if(type == SOCKETS) {
	    r = MmuReadVirtualRegion(cr3, pipinfo - 0x08, &tmp, sizeof(hvm_address));
	    if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

	    r = MmuReadVirtualRegion(cr3, tmp + OFFSET_SOCKET_REMOTE_PORT, &remote_port, sizeof(remote_port));
	    if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;
	  }

	  if(type == UDP) {

	    r = MmuReadVirtualRegion(cr3, pipinfo + OFFSET_UDP_IPv6_1, &tmp, sizeof(hvm_address));
	    if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

	    r = MmuReadVirtualRegion(cr3, tmp + OFFSET_UDP_IPv6_2, &ipv6, sizeof(ipv6));
	    if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;
	  }
	  else {

	    r = MmuReadVirtualRegion(cr3, pipinfo + OFFSET_IPv6_1, &tmp, sizeof(hvm_address));
	    if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

	    r = MmuReadVirtualRegion(cr3, tmp + OFFSET_IPv6_2, &ipv6, sizeof(ipv6));
	    if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;
	  }
	  
	  if(ipv6 != 0x17) ipv6 = 0;

	  if(type == UDP) r = MmuReadVirtualRegion(cr3, pipinfo - 0x14, &tmp, sizeof(hvm_address));
	  else r = MmuReadVirtualRegion(cr3, pipinfo - 0x0c, &tmp, sizeof(hvm_address));
	  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

	  if(tmp != 0) {
	  
	    if(ipv6) {

	      for(k = 0, h = 0; k < 0xe; k+=2, h++){
		r = MmuReadVirtualRegion(cr3, tmp + OFFSET_LISTEN_LOCAL_IP + k, &local_ipv6[h], sizeof(local_ipv6[0]));
		if(r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;
	      }
	    }
	    else r = MmuReadVirtualRegion(cr3, tmp + OFFSET_LISTEN_LOCAL_IP, &local_ip, sizeof(local_ip));
	    if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;
	  }
	  else {
	    
	    if(ipv6) local_ipv6[0] = local_ipv6[1] = local_ipv6[2] = local_ipv6[3] = local_ipv6[4] = local_ipv6[5] = local_ipv6[6] = local_ipv6[7] = 0;
	    else local_ip = 0;
	  }

	  if(type == UDP) r = MmuReadVirtualRegion(cr3, pipinfo + OFFSET_UDP_PEPROCESS, &peprocess, sizeof(hvm_address));
	  else r = MmuReadVirtualRegion(cr3, pipinfo + OFFSET_SOCKET_PEPROCESS, &peprocess, sizeof(hvm_address));
	  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

	  r = MmuReadVirtualRegion(cr3, peprocess + OFFSET_EPROCESS_UNIQUEPID, &pid, sizeof(pid));
	  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

	  if(data_found < maxsize && pid > 0) {
	    
	    

	    vmm_memset(&buf[data_found], 0, sizeof(SOCKET));
	    buf[data_found].state       = SocketStateListen;
	    buf[data_found].local_port  = vmm_ntohs(local_port);
	    buf[data_found].pid         = pid;
	    buf[data_found].protocol    = type==UDP ? 17 : 6;

	    if(type == SOCKETS) buf[data_found].remote_port = vmm_ntohs(remote_port);

	    if(ipv6) {

	      for(k = 0; k < 8; k++)
		buf[data_found].local_ipv6[k]   = local_ipv6[k];

	      buf[data_found].local_ip = -1;
	    }
	    else {
	      buf[data_found].local_ip  = local_ip;
	    }

	    data_found++;
	  }

	  r = MmuReadVirtualRegion(cr3, pipinfo, &pipinfo, sizeof(hvm_address));
	  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;
	}
      }
    }
    skip = 0;
  }

  *psize = data_found;

  Log("[HyperDbg] Search of %s finished. Found: %d", type==UDP?"UDP connections":"sockets", data_found);
  
  return HVM_STATUS_SUCCESS;
}

hvm_status Windows7BuildSocketList(hvm_address cr3, SOCKET* buf, Bit32u maxsize, Bit32u *psize)
{
  hvm_status r;
  unsigned int n1, n2, n3;

  r = Windows7FindNetworkConnections(cr3, buf, maxsize, &n1);
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

  r = Windows7FindNetworkData(cr3, buf + n1, maxsize - n1, &n2, SOCKETS);
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;
  
  r = Windows7FindNetworkData(cr3, buf + n1 + n2, maxsize - (n1+n2), &n3, UDP);
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;  

  *psize = (n1+n2+n3);

  return r;
}

#else

static hvm_status WindowsFindNetworkConnections(hvm_address cr3, SOCKET *buf, Bit32u maxsize, Bit32u *psize)
{
  hvm_status r;
  hvm_address table_base, table_entry;
  unsigned int i, j;
  Bit32u table_size;  
  TCPT_OBJECT obj;
  MODULE_DATA tcp_module;

  r = WindowsFindModuleByName(cr3, "tcpip.sys", &tcp_module);
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

  
  r = MmuReadVirtualRegion(cr3, tcp_module.baseaddr + OFFSET_TCB_TABLE, &table_base, sizeof(table_base));
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

  
  r = MmuReadVirtualRegion(cr3, tcp_module.baseaddr + OFFSET_TCB_TABLE_SIZE, &table_size, sizeof(table_size));
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

  j = 0;
  for (i=0; i<table_size && i<maxsize; i++) {
    r = MmuReadVirtualRegion(cr3, table_base + (i*4), &table_entry, sizeof(table_entry));
    if (r != HVM_STATUS_SUCCESS) 
      continue;

    if (!table_entry) {
      
      continue;
    }
    
    r = MmuReadVirtualRegion(cr3, table_entry, &obj, sizeof(obj));
    if (r != HVM_STATUS_SUCCESS) 
      continue;
    vmm_memset(&buf[j], 0, sizeof(SOCKET));

    buf[j].state       = SocketStateEstablished;
    buf[j].remote_ip   = obj.RemoteIpAddress;
    buf[j].local_ip    = obj.LocalIpAddress;
    buf[j].remote_port = vmm_ntohs(obj.RemotePort);
    buf[j].local_port  = vmm_ntohs(obj.LocalPort);
    buf[j].pid         = obj.Pid;
    buf[j].protocol    = 7;	
    j++;
  }

  *psize = j;
  return HVM_STATUS_SUCCESS;
}

static hvm_status  WindowsFindNetworkSockets(hvm_address cr3, SOCKET *buf, Bit32u maxsize, Bit32u *psize)
{
  hvm_status r;
  MODULE_DATA tcp_module;
  hvm_address next, table_base, table_entry;
  Bit32u  local_ip, pid, table_size;
  Bit16u local_port, protocol;
  LARGE_INTEGER create_time;

  unsigned int i, j;

  r = WindowsFindModuleByName(cr3, "tcpip.sys", &tcp_module);
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

  
  r = MmuReadVirtualRegion(cr3, tcp_module.baseaddr + OFFSET_ADDROBJ_TABLE, &table_base, sizeof(table_base));
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

  
  r = MmuReadVirtualRegion(cr3, tcp_module.baseaddr + OFFSET_ADDROBJ_TABLE_SIZE, &table_size, sizeof(table_size));
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

  j = 0;
  for (i=0; i<table_size; i++) {
    r = MmuReadVirtualRegion(cr3, table_base + (i*4), &table_entry, sizeof(table_entry));
    if (r != HVM_STATUS_SUCCESS) 
      continue;

    if (!table_entry) {
      
      continue;
    }

    while (table_entry && MmIsAddressValid((PVOID) table_entry)) {
      r = MmuReadVirtualRegion(cr3, table_entry + OFFSET_ADDRESS_OBJECT_NEXT, &next, sizeof(next));
      if (r != HVM_STATUS_SUCCESS) break;

      r = MmuReadVirtualRegion(cr3, table_entry + OFFSET_ADDRESS_OBJECT_LOCALIP, &local_ip, sizeof(local_ip));
      if (r != HVM_STATUS_SUCCESS) break;

      r = MmuReadVirtualRegion(cr3, table_entry + OFFSET_ADDRESS_OBJECT_LOCALPORT, &local_port, sizeof(local_port));
      if (r != HVM_STATUS_SUCCESS) break;

      r = MmuReadVirtualRegion(cr3, table_entry + OFFSET_ADDRESS_OBJECT_PID, &pid, sizeof(pid));
      if (r != HVM_STATUS_SUCCESS) break;

      r = MmuReadVirtualRegion(cr3, table_entry + OFFSET_ADDRESS_OBJECT_PROTOCOL, &protocol, sizeof(protocol));
      if (r != HVM_STATUS_SUCCESS) break;

      r = MmuReadVirtualRegion(cr3, table_entry + OFFSET_ADDRESS_OBJECT_CREATETIME, &create_time, sizeof(create_time));
      if (r != HVM_STATUS_SUCCESS) break;

      local_port = vmm_ntohs(local_port);

      vmm_memset(&buf[j], 0, sizeof(SOCKET));
      buf[j].state       = SocketStateListen;
      buf[j].local_ip    = local_ip;
      buf[j].local_port  = local_port;
      buf[j].pid         = pid;
      buf[j].protocol    = protocol;

      j++;
      table_entry = next;
    }
  }

  *psize = j;

  return HVM_STATUS_SUCCESS;
}

hvm_status WindowsBuildSocketList(hvm_address cr3, SOCKET* buf, Bit32u maxsize, Bit32u *psize)
{
  hvm_status r;
  unsigned int n1, n2;

  r = WindowsFindNetworkConnections(cr3, buf, maxsize, &n1);
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

  r = WindowsFindNetworkSockets(cr3, buf + n1, maxsize - n1, &n2);
  if (r != HVM_STATUS_SUCCESS) return HVM_STATUS_UNSUCCESSFUL;

  *psize = (n1+n2);

  return HVM_STATUS_SUCCESS;
}

#endif

#define MAX_RANGES 16
#define MAX_DKC_PAGES 4096
#define MAX_SKC_PAGES 1024

hvm_status WindowsModuleClassify(hvm_address cr3)
{
  IMAGE_DOS_HEADER      IDH;
  IMAGE_FILE_HEADER     IFH;
  IMAGE_OPTIONAL_HEADER IOH;
  IMAGE_SECTION_HEADER  ISH;
  hvm_status r;
  hvm_address section_offset, page;
  MODULE_DATA prev, next;
  Bit32u count_module = 0, i, j, k, nt_signature;
  Bit16u NoS;
  CODE_RANGE ranges[MAX_RANGES];
  hvm_bool entry_found, debug = TRUE;
  
  
  ComPrint("[MmuClassify] Starting to classify module and kernel pages [cr3: %08x]\n", cr3);
  r = ProcessGetNextModule(context.GuestContext.cr3, NULL, &next);

  for (i=0; ; i++) {
    if (r == HVM_STATUS_END_OF_FILE) {
      
      break;
    } else if (r != HVM_STATUS_SUCCESS) {
      ComPrint("[MmuClassify] Error reading %dth module\n", i);
      return HVM_STATUS_UNSUCCESSFUL;
    }
    count_module++;

    if(debug) ComPrint("[MmuClassify] Module %d: %s. Base: %08x Size: %08x Entry: %08x\n", i, next.name, next.baseaddr, next.sizeofimage, next.entrypoint);
    
    if(vmm_strlen((Bit8u *)next.name) == 0)
      goto next;
    
    r = MmuReadVirtualRegion(cr3, next.baseaddr, &IDH, sizeof(IDH));
    if(!(HVM_SUCCESS(r))) {
      ComPrint("[MmuClassify] Error reading from baseaddr %08x\n", next.baseaddr);
      goto next;
    }

    
    r = MmuReadVirtualRegion(cr3, next.baseaddr + IDH.e_lfanew, &nt_signature, 4); 
    if(!(HVM_SUCCESS(r))) {
      ComPrint("[MmuClassify] Error reading signature\n");
      goto next;
    }

    
    if(nt_signature != 0x00004550) {
      ComPrint("[MmuClassify] Wrong Signature: %08x\n", nt_signature);
      goto next;
    }
    
    
    r = MmuReadVirtualRegion(cr3, next.baseaddr + IDH.e_lfanew + 4, &IFH, sizeof(IFH)); 
    if(!(HVM_SUCCESS(r))) {
      ComPrint("[MmuClassify] Error reading IFH\n");
      goto next;
    }
    NoS = IFH.NumberOfSections;
    
    
    r = MmuReadVirtualRegion(cr3, next.baseaddr + IDH.e_lfanew + 24, &IOH, sizeof(IOH)); 
    if(!(HVM_SUCCESS(r))) {
      ComPrint("[MmuClassify] Error reading IOH\n");
      goto next;
    }

    
    
    
    
    
    
    
    
    
    
    
    



    
    
    for(k = 0; k < MAX_RANGES; k++) {
      ranges[k].start = 0;
      ranges[k].end = 0;
    }
    k = 0; 
    for(j = 0; j < NoS; j++) {
      
      section_offset = next.baseaddr + (IDH.e_lfanew + 24) + IFH.SizeOfOptionalHeader + j *sizeof(ISH);
      
      r = MmuReadVirtualRegion(cr3, section_offset, &ISH, sizeof(ISH)); 
      if(!(HVM_SUCCESS(r))) {
	ComPrint("[MmuClassify] Error reading ISH\n");
	goto next;
      }
      
      if(debug) ComPrint("[MmuClassify] Section @ %08x name: %s size: %08x base: %08x Characteristics: %08x CODE: %d k: %d\n", section_offset, ISH.Name, ISH.Misc.VirtualSize, next.baseaddr + ISH.VirtualAddress, ISH.Characteristics, (ISH.Characteristics & IMAGE_SCN_CNT_CODE)?1:0, k);
    }

  next:
    
    prev = next;
    r = ProcessGetNextModule(context.GuestContext.cr3, &prev, &next);
  }

    
    
  return HVM_STATUS_SUCCESS;
 error:
  ComPrint("[MmuClassify] WOOO THIS IS BAD!\n");
  return HVM_STATUS_UNSUCCESSFUL;
}
