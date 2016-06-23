

#include "vmmstring.h"
#include "godfather.h"
#include "mmu.h"
#include "ept.h"
#include "x86.h"
#include "extern.h"
#include "video.h"
#include "common.h"
#include "comio.h"

#define MAX_PROTECTED_PTS  0x100000
#define TRACKING_ENABLED          1

GOD_BP god_bps[MAX_GOD_BPS];
PROTECTED protected[MAX_PROTECTED_PROCESSES];


TRACED_PAGE traced[MAX_TRACED];
VA_TRACED_PAGE va_traced[MAX_TRACED]; 
hvm_bool protected_page_tables[MAX_PROTECTED_PTS]; 
Bit32u first_free = 0;
Bit32u pds;
Bit32u pts;
Bit32u procs;

#ifdef TRACKING_ENABLED
Bit64u curr;
Bit64u last;
Bit64u total;









#define MS1       2670000ULL
#define MS10     26700000ULL
#define MS100   267000000ULL
#define MS500  1335000000ULL
#define S1     2670000000ULL









#define THRESHOLD_100M             25600
#define THRESHOLD_150M             38400
#define THRESHOLD_200M             51200
#define THRESHOLD_250M             64000
#define TIME_THRESHOLD                S1
#define EXPLOIT_THRESHOLD          THRESHOLD_150M
#define MAX_LAST_TRACED              500
Bit32u  LAST_TRACED =    MAX_LAST_TRACED;

FREQ_INFO freqs[MAX_LAST_TRACED];

hvm_bool done;
Bit32u last_traced[MAX_LAST_TRACED];
Bit64u last_scanned;
hvm_address target_cr3;



#endif

hvm_status GodInit()
{
  vmm_memset(protected, 0, MAX_PROTECTED_PROCESSES*sizeof(PROTECTED));
  vmm_memset(god_bps, 0, MAX_GOD_BPS*sizeof(GOD_BP));
  vmm_memset(protected_page_tables, 0, MAX_PROTECTED_PTS);
  vmm_memset(freqs, 0, MAX_LAST_TRACED*sizeof(FREQ_INFO));
  vmm_memset(va_traced, 0, MAX_TRACED*sizeof(VA_TRACED_PAGE));
#ifdef TRACKING_ENABLED
  done = TRUE;
  target_cr3 = 0;
  total = last_scanned = 0;
#endif
  
}

hvm_bool GodIsPtProtected(hvm_address pt_base)
{
  if((pt_base >> 12) < MAX_PROTECTED_PTS) {
    return protected_page_tables[(pt_base >> 12)];
  }
  else {
    GodLog("[GodIsPtProtected] %08x out of range!\n", pt_base >> 12);
    __asm__ __volatile__("ud2\n");
  }
  
  return 0;
}

void GodSetPtProtection(hvm_address pt_base, hvm_bool protection)
{
  if((pt_base >> 12) < MAX_PROTECTED_PTS) {
    protected_page_tables[(pt_base >> 12)] = protection;
  }
  else {
    GodLog("[GodSetPtProtection] %08x out of range!\n", pt_base >> 12);
    __asm__ __volatile__("ud2\n");
  }
}


Bit32u GodFindProtectedProcess(hvm_address cr3)
{
  Bit32u i = 0;
  while(i < MAX_PROTECTED_PROCESSES){
    if(protected[i].cr3 == cr3)
      break;
    i++;
  }
  return i;
}


Bit32u GodFindTracedPage(hvm_address pa)
{
  Bit32u i = pa >> 12;
  if(i >= MAX_TRACED) {
    return MAX_TRACED;
  }

  if(traced[i].ref_count == 0)		
    return MAX_TRACED;

  return i;
}

PTE GodGetVaTracedPage(hvm_address va)
{
  return va_traced[va >> 12].pte;
}













hvm_status GodAddProtectedProcess(hvm_address cr3, Bit32u *index)
{
  Bit32u i = first_free;
  protected[i].cr3 = cr3;
  protected[i].protected_pts = 0;
  protected[i].to_be_removed = FALSE;
  *index = i;
  
  while(i < MAX_PROTECTED_PROCESSES) {
    if(protected[i].cr3 == 0) {
      first_free = i;
      return HVM_STATUS_SUCCESS;
    }
    i++;
  }
  return HVM_STATUS_UNSUCCESSFUL;
}

#ifdef TRACKING_ENABLED

void GodDumpAllocInfo()
{
  Bit8u log[256];

  
  RegRdtsc(&curr);
  if(curr-last > TIME_THRESHOLD) {
    
    
    
    GodLog("time: %lld | total protected: %lld | %lld", curr, total, last_scanned);
    last = curr;
  }
  
  
  
  
  
  

  GodDumpSomePages();
}

void GodDumpSomePages()
{
  hvm_status r;
  Bit32u count, print = 10;
  Bit32s i;
  Bit32u j, k, h, offset = 0;
  hvm_address pagedump[4096/4], *p, pa;
  PTE pte;
  Bit8u log[256];
  hvm_bool found = FALSE;
 
  if(total >= EXPLOIT_THRESHOLD && done == FALSE) {

    
    
    
    

    
    
    
    

    

    
    for(i = LAST_TRACED-1; i >= 0; i--) {

      
      

      

      pa = GodTracedGetPa(last_traced[i]);

      
    
    
    
    
    
      
      r = MmuReadPhysicalRegion(pa, pagedump, sizeof(pagedump));
      if(r != HVM_STATUS_SUCCESS) {
	GodLog("[GodDumpAllocInfo] Unable to read %d bytes from PA %08hx (index: %d)", sizeof(pagedump), pa, i);
	__asm__ __volatile__("ud2\n");
      }

      
      
      
      
      
      
      
      
      
      
      
      
      
      
      
      
      
      

      
      for(offset = 0; offset < 1; offset++) {

        
        p = (hvm_address *)((hvm_address)pagedump+offset);
	for(j = 0; j < 4096/4-offset; j++) {

	  pte = va_traced[p[j] >> 12].pte;

	
	
	
	

	  if(!MmuIsAddressValid(target_cr3, p[j]) || !pte.Present || pte.PageBaseAddr == 0)
	    continue;

	
	  if(!pte.Writable) {
	
	
	    
	    GodAddFreqPage(i, p[j]);
	  }
	
	
	
	
	}
	

	
	
	
	

	
	
	
	
	
	
	
	
      }
    }
    
    done = TRUE;
    
    
    

    unsigned long long sum = 0;
    for(h = 0; h < LAST_TRACED; h++) {
      for(j = 0; j < freqs[h].first_free; j++) {
	sum += freqs[h].freq_exec[j].count;
      }
    }
    unsigned long long avg = sum/LAST_TRACED;
    
    
    
    if (avg >= 16) {
      unsigned long long var = 0;
      for(h = 0; h < LAST_TRACED; h++) {
	for(j = 0; j < freqs[h].first_free; j++) {
	  var += ((freqs[h].freq_exec[j].count-avg)*(freqs[h].freq_exec[j].count-avg))/LAST_TRACED;
	}
      }
      if (var < 10) {
	GodLog("FALSO POSITIVO!!! media %d, varianza %d", avg, var);
	
	
	
	
	
	
      }
      else 
	GodLog("OK: varianza %d", var);
    }
    else
      GodLog("OK: media: %d", avg);

    vmm_memset(freqs, 0, MAX_LAST_TRACED*sizeof(FREQ_INFO));
  }
  
  
  
  
  
  
}
#endif 

hvm_status GodAddFreqPage(Bit32u index, hvm_address va)
{
  int i, f = freqs[index].first_free;

  for(i = 0; i < f; i++)
    if(va == freqs[index].freq_exec[i].address) {
      freqs[index].freq_exec[i].count++;
      return HVM_STATUS_SUCCESS;
    }

  
  freqs[index].freq_exec[f].address = va;
  freqs[index].freq_exec[f].count = 1;
  freqs[index].first_free++;
}



  




















hvm_status GodAddTracedPage(hvm_address pa, hvm_address va, PTE pte, Bit32u *index)
{
  Bit32u j, i = pa >> 12;

  if(i >= MAX_TRACED) {
    return HVM_STATUS_UNSUCCESSFUL;
  }

  traced[i].ref_count++;
  traced[i].va = va;
  *index = i;										

#ifdef TRACKING_ENABLED

  if((total - last_scanned) == LAST_TRACED-1 && traced[i].ref_count == 1) {
    done = FALSE;
    last_scanned = total+1;
  }

  if(traced[i].ref_count == 1) {
    int mod = total/LAST_TRACED;
    mod *= LAST_TRACED;
    mod = total - mod; 
    last_traced[mod] = i;
    
    va_traced[va >> 12].pte = pte;
  }

  
  if(traced[i].ref_count == 1) {
    total++;
    GodDumpAllocInfo();
  }
#endif

  return HVM_STATUS_SUCCESS;
}

void GodRemoveProtectedProcess(Bit32u index)
{
  Bit8u log[256];

  protected[index].cr3 = 0;
  protected[index].protected_pts = 0;

  if(index < first_free)
    first_free = index;

#ifdef TRACKING_ENABLED
  if(first_free == 0) {
    
    
    
    
    total = 0;
    last_scanned = 0;
    
  }
#endif
}

hvm_status GodRemoveTracedPage(Bit32u index)
{
  if(index >= MAX_TRACED) {
    return HVM_STATUS_UNSUCCESSFUL;
  }

  traced[index].ref_count--;

#ifdef TRACKING_ENABLED
	
  if(traced[index].ref_count == 0) {
    total--;
    GodDumpAllocInfo();
  }
#endif

  return HVM_STATUS_SUCCESS;
}

hvm_status GodRemoveVATracedPage(hvm_address va)
{
  if((va >> 12) >= MAX_TRACED)
    return HVM_STATUS_UNSUCCESSFUL;

  vmm_memset(&va_traced[va >> 12], 0, sizeof(PTE));

  return HVM_STATUS_SUCCESS;
}

hvm_bool GodIsToBeRemoved(Bit32u index)
{
  return protected[index].to_be_removed;
}

void GodSetToBeRemoved(Bit32u index)
{
  protected[index].to_be_removed = TRUE;
}

void GodIncPTs(Bit32u index)
{
  protected[index].protected_pts++;
}

void GodDecPTs(Bit32u index)
{
  protected[index].protected_pts--;
}

Bit32u GodGetPTs(Bit32u index)
{
  return protected[index].protected_pts;
}

void GodTracedSetWritten(Bit32u index, Bit64u written)
{
  traced[index].written = written;
}

void GodTracedSetExecuted(Bit32u index, Bit64u executed)
{
  traced[index].executed = executed;
}

hvm_address GodTracedGetPa(Bit32u index)
{
  return index << 12;
}






Bit64u GodTracedGetWritten(Bit32u index)
{
  return traced[index].written;
}

Bit64u GodTracedGetExecuted(Bit32u index)
{
  return traced[index].executed;
}

hvm_address GodTracedGetRefCount(Bit32u index)
{
  return traced[index].ref_count;
}

Bit32u GodAddBP(hvm_address phy_eip)
{
  hvm_status r;
  Bit8u old_opcode;
  Bit32u i = 0;
  Bit8u bp_opcode = 0xcc;
  
  r = MmuReadPhysicalRegion(phy_eip, &old_opcode, 1);
  if(r == HVM_STATUS_UNSUCCESSFUL) {
    GodLog("[GodAddBP] UNABLE TO READ FROM TARGET: %08x", phy_eip);
    return MAX_GOD_BPS;
  }
  r = MmuWritePhysicalRegion(phy_eip, &bp_opcode, 1);
  if(r == HVM_STATUS_UNSUCCESSFUL) {
    GodLog("[GodAddBP] UNABLE TO WRITE TARGET: %08x", phy_eip);
    return MAX_GOD_BPS;
  }
  for(; i < MAX_GOD_BPS; i++) {
    if(god_bps[i].phy_eip == 0 && god_bps[i].old_opcode == 0) {
      god_bps[i].phy_eip = phy_eip;
      god_bps[i].old_opcode = old_opcode;
      return i;
    }
  }
  return MAX_GOD_BPS;
}

Bit32u GodFindBP(hvm_address phy_eip)
{
  Bit32u i = 0;
  for(; i < MAX_GOD_BPS; i++) {
    if(god_bps[i].phy_eip == phy_eip) {
      return i;
    }
  }
  return MAX_GOD_BPS;
}

hvm_status GodRemoveBP(Bit32u index)
{
  Bit8u old_opcode;
  hvm_address phy_eip;
  hvm_status r;

  phy_eip = god_bps[index].phy_eip;
  old_opcode = god_bps[index].old_opcode;

  god_bps[index].phy_eip = 0;
  god_bps[index].old_opcode = 0;
  
  r = MmuWritePhysicalRegion(phy_eip, &old_opcode, 1);
  return r;
}

PPTE GodGetProtectedProcessPageDir(Bit32u index)
{
  return protected[index].pd;
}

hvm_status GodProtectAllPTs(hvm_address cr3, Bit32u index)
{
  Bit32u procIndex, i, j, count, count_pages, traced_index;
  hvm_address pde_base;
  PTE page_table[1024];
  PPTE page_dir;
  char log[256];
  hvm_status r;

  i = j = count = count_pages = 0;
  
  procIndex = GodFindProtectedProcess(cr3);
  page_dir = protected[procIndex].pd;

  GodLog("Protecting PTs for cr3: %08x", cr3);
  r = MmuReadPhysicalRegion(cr3, page_dir, 1024*sizeof(PTE));
  if(r == HVM_STATUS_UNSUCCESSFUL) {
    GodLog("Failed to read %d bytes from %08x", 1024*sizeof(PTE), cr3);
    return r;
  }

  target_cr3 = cr3;

  EPTRemovePTperms(cr3, WRITE);
  GodSetPtProtected(cr3);
  GodIncPTs(index);
  count++;

  while(i < 1024) {
    if(i > 511 && i != 768) { i++; continue; }
    
    

    if(page_dir[i].PageBaseAddr != 0 && page_dir[i].Present && page_dir[i].LargePage != 1) {
      
      
      
      

      
      if(GodIsBlackListed((page_dir[i].PageBaseAddr << 12)) == FALSE) {
	EPTRemovePTperms((page_dir[i].PageBaseAddr << 12), WRITE);
	GodSetPtProtected((page_dir[i].PageBaseAddr << 12));
	GodIncPTs(index);
	pts++;
	count++;

	
	r = MmuReadPhysicalRegion(page_dir[i].PageBaseAddr << 12, page_table, 1024*sizeof(PTE));
	if(r == HVM_STATUS_UNSUCCESSFUL) {
	  GodLog("Failed to read %d bytes from %08x", 1024*sizeof(PTE), page_dir[i].PageBaseAddr << 12);
	  return r;
	}
	if(i != 768) {
	  for(j = 0; j < 1024; j++) {
	    if(page_table[j].Present) {
	      

	      
	      
	      

	      if(j%32 == 0) {
		
		
		
		GodLog("%d %d", i, j);
	      }

	      GodAddTracedPage((page_table[j].PageBaseAddr << 12), (i<<22|j<<12), page_table[j], &traced_index);
	      EPTRemovePTperms((page_table[j].PageBaseAddr << 12), WRITE); 
	      count_pages++;
	    }
	  }
	}
      }
    }
    i++;
  }
  GodLog("Protected< %d page tables and %d pages", count, count_pages);
  return HVM_STATUS_SUCCESS;
}

pt_status GodCheckMapping(PPTE pold, PPTE pnew)
{
  if(*(Bit32u *)(pold) == 0 && *(Bit32u *)(pnew) == 0xffffffff)
    return GOD_IGNORE;				
	
  if(pnew->Present == 1) { 
    if(pold->Present == 0) {
      if(pnew->PageBaseAddr == 0) 
				return GOD_IGNORE;
      else
				return GOD_MAP;
    }
    else { 
      if(pnew->PageBaseAddr == pold->PageBaseAddr) {
	if((pnew->Writable != pold->Writable) || (pnew->Owner != pold->Owner) || (pnew->LargePage != pold->LargePage)) {
	  return GOD_CHANGE_FLAG;
	}
	else { 
	  return GOD_IGNORE;
	}
      }
      else { 
	return GOD_CHANGE_PHY;
      }
    }
  }
  else { 
    if(pold->Present == 1)
      return GOD_UNMAP;
    else
      return GOD_IGNORE; 
  }
}



  


void GodDumpViolation(PEVENT_ARGUMENTS args)
{
  hvm_status r;
  char proc_name[16];
  
  hvm_phy_address phy;
  Bit32u i = 0;
  ud_t ud_obj;
  Bit32u insn_len;
  char *insn_hex;

  
  
  

  
  

  
  
  
  
  
  
  
  
  
  

  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  

  
  
  
  
  
  


  
  
  
  
}

hvm_bool GodIsBlackListed(hvm_address base)
{
  return FALSE;
  switch(base) {
  case 0x1aa4b000:
    return TRUE;
  case 0x17936000:
    return TRUE;
  default:
    return FALSE;
  }
}







hvm_address user_base  = 0;	
hvm_address user_size  = 0;	
hvm_address user_cr3   = 0;
hvm_address user_row   = 0;	
hvm_address user_index = 0;	
hvm_bool    user_init = FALSE;



void GodUserLogSetInfo(hvm_address cr3, hvm_address base, Bit32u row_num, Bit32u row_size)
{
  user_cr3  = cr3;
  user_base = base;
  user_row  = row_num;
  user_size = row_size;
  user_init = TRUE;
}

hvm_status GodUserLog(char *log)
{
  hvm_status r;
  Bit32u msg_len = 0;

  if(user_init == FALSE)
    return HVM_STATUS_UNSUCCESSFUL;
  
  msg_len = vmm_strlen(log);
  if(msg_len > user_size)
    return HVM_STATUS_UNSUCCESSFUL;

  
  r = MmuWriteVirtualRegion(user_cr3, (user_base + user_index * user_size), log, msg_len);
  if(r == HVM_STATUS_UNSUCCESSFUL) {
    GodLog("[GodUserLog] WARNING UNABLE TO WRITE TO USER LOG!");
    return r;
  }
  
  user_index++;
  if(user_index == user_row)
    user_index = 0;

  return HVM_STATUS_SUCCESS;
}

hvm_status GodUserLogN(char *log, Bit32u msg_len)
{
  hvm_status r;

  if(user_init == FALSE)
    return HVM_STATUS_UNSUCCESSFUL;

  r = MmuWriteVirtualRegion(user_cr3, (user_base + user_index * user_size), log, msg_len);
  if(r == HVM_STATUS_UNSUCCESSFUL) {
    GodLog("[GodUserLogN] WARNING UNABLE TO WRITE TO USER LOG!");
    return r;
  }
  
  user_index++;
  if(user_index == user_row)
    user_index = 0;

  return HVM_STATUS_SUCCESS;
}


hvm_status GodGetStackTrace(hvm_address *trace, Bit32u size)
{
  Bit32u i = 0;
  hvm_address current_frame, current_rip;
  hvm_status r;

  if(!trace)
    return HVM_STATUS_UNSUCCESSFUL;

  current_frame = context.GuestContext.rbp;
  while(i < size) {
    r = MmuReadVirtualRegion(context.GuestContext.cr3, current_frame+4, &current_rip, sizeof(current_rip));

    if(r != HVM_STATUS_SUCCESS) 
      return r;

    trace[i] = current_rip;
    
    
    r = MmuReadVirtualRegion(context.GuestContext.cr3, current_frame, &current_frame, sizeof(current_frame));
    if (r != HVM_STATUS_SUCCESS) 
      return r;

    i++;
  }
  return HVM_STATUS_SUCCESS;
}

hvm_status GodDumpStackTrace(void)
{
  hvm_address trace[8];
  char log[256];
  hvm_status r;
  Bit32u i = 0;
  vmm_memset(trace, 0, sizeof(trace));

  r = GodGetStackTrace(trace, 8);
  
  while(i < 8 && trace[i] != 0) {
    

    vmm_memset(log, 0, 256);
    vmm_snprintf(log, 256, "%d %08hx [cr3: %08hx]\n", i, trace[i], context.GuestContext.cr3);
    GodUserLog(log);

    i++;
  }
}
