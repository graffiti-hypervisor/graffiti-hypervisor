


#ifdef GUEST_LINUX
#include <linux/kernel.h>
#include <linux/mempool.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <asm/io.h> 
#endif

#include "common.h"
#include "debug.h"
#include "mmu.h"
#include "x86.h"
#include "vmmstring.h"





#define MmuPrint(fmt, ...) 


#ifdef ENABLE_PAE
#define VIRTUAL_PD_BASE     0xC0600000
#else
#define VIRTUAL_PD_BASE     0xC0300000 
#endif


#define VIRTUAL_PT_BASE     0xC0000000 

static void *hostpt = NULL;





static hvm_status MmuFindUnusedPTE(hvm_address* pdwLogical);
static hvm_bool   MmuGetCr0WP(void);

#if 0
static void       MmuPrintPDEntry(PPTE pde);
static void       MmuPrintPTEntry(PPTE pte);
static hvm_status MmuFindUnusedPDE(hvm_address* pdwLogical);
#endif
  






hvm_address MmuGetHostPT(void)
{
  return (hvm_address)hostpt;
}

hvm_status MmuInit(hvm_address *pcr3)
{
  hvm_status r;
  hvm_phy_address phy;
  hvm_address cr3, pde_addr;
  PTE pde;
    
  cr3 = RegGetCr3();






  




  

  






  
























  
  *pcr3 = cr3;
  
  return HVM_STATUS_SUCCESS;
  
 error:
  if (hostpt) {

#ifdef GUEST_WINDOWS
    ExFreePoolWithTag(hostpt, 'gbdh');
#elif defined GUEST_LINUX
    kfree(hostpt);
#endif

    hostpt = NULL;
  }
  return HVM_STATUS_UNSUCCESSFUL;
}


hvm_status MmuFini(void)
{
  if (hostpt) {
#ifdef GUEST_WINDOWS
    ExFreePoolWithTag(hostpt, 'gbdh');
#elif defined GUEST_LINUX
    kfree(hostpt);
#endif
    hostpt = NULL;
  }
  
  return HVM_STATUS_SUCCESS;
}

hvm_bool MmuIsAddressWritable(hvm_address cr3, hvm_address va)
{
  hvm_status r;
  PTE p;
  hvm_bool isLarge;

  if (!MmuIsAddressValid(CR3_ALIGN(cr3), va)) {
    return FALSE;
  }

  
  if(!MmuGetCr0WP()) { 
    MmuPrint("[MMU] CR0.WP == 0\n");
    return TRUE;
  }

  r = MmuGetPageEntry(CR3_ALIGN(cr3), va, &p, &isLarge);
  if (r != HVM_STATUS_SUCCESS) {
    return FALSE;
  }

  return (p.Writable != 0);
}

hvm_bool MmuIsAddressValid(hvm_address cr3, hvm_address va)
{
  hvm_status r;
  hvm_bool isLarge;

  r = MmuGetPageEntry(CR3_ALIGN(cr3), va, NULL, &isLarge);

  return (r == HVM_STATUS_SUCCESS);
}

hvm_status MmuGetPhysicalAddress(hvm_address cr3, hvm_address va, hvm_phy_address* pphy)
{
  hvm_status r;
  PTE pte;
  hvm_bool isLarge;

  r = MmuGetPageEntry(CR3_ALIGN(cr3), va, &pte, &isLarge); 
    
  if (r != HVM_STATUS_SUCCESS) {
    return HVM_STATUS_UNSUCCESSFUL;
  }

  if (isLarge) {
    *pphy = LARGEFRAME_TO_PHY(pte.PageBaseAddr) + LARGEPAGE_OFFSET(va);
    MmuPrint("[MMU] MmuGetPhysicalAddress(LARGE) cr3: %.8x frame: %.8x va: %.8x phy: %.8x\n", 
	     CR3_ALIGN(cr3), pte.PageBaseAddr, va, *pphy);
    return HVM_STATUS_SUCCESS;
  }

  *pphy = FRAME_TO_PHY(pte.PageBaseAddr) + MMU_PAGE_OFFSET(va);

  return HVM_STATUS_SUCCESS;
}

hvm_status MmuMapPhysicalPage(hvm_phy_address phy, hvm_address* pva, PPTE pentryOriginal)
{
  hvm_status r;
  hvm_address dwEntryAddress, dwLogicalAddress;
  PTE *pentry;
  
  
  MmuPrint("[MMU] MmuMapPhysicalPage() Searching for unused PTE...\n");
  r = MmuFindUnusedPTE(&dwLogicalAddress);
  MmuPrint("[MMU] MmuMapPhysicalPage() Unused PTE found at %.8x\n", dwLogicalAddress);

  if (r != HVM_STATUS_SUCCESS)
    return HVM_STATUS_UNSUCCESSFUL;
  
#ifdef GUEST_WINDOWS
  dwEntryAddress = VIRTUAL_PT_BASE + ((( VA_TO_PDE(dwLogicalAddress) ) << 12) |  (VA_TO_PTE(dwLogicalAddress) * sizeof(PTE)));
  
#elif defined GUEST_LINUX 
  
  MmuPrint("dwLogicalAddress: %08x", dwLogicalAddress);
  MmuVirtToPTE(dwLogicalAddress, &dwEntryAddress);
  MmuPrint("PTE@%08x", dwEntryAddress);
#endif

  pentry = (PPTE) dwEntryAddress;

  
  *pentryOriginal = *pentry;

  
  pentry->Present         = 1;
  pentry->Writable        = 1;
  pentry->Owner           = 1;
  pentry->WriteThrough    = 0;
  pentry->CacheDisable    = 0;
  pentry->Accessed        = 0;
  pentry->Dirty           = 0;
  pentry->LargePage       = 0;
  pentry->Global          = 0;
  pentry->ForUse1         = 0;
  pentry->ForUse2         = 0;
  pentry->ForUse3         = 0;
  pentry->PageBaseAddr    = PHY_TO_FRAME(phy);

  hvm_x86_ops.mmu_tlb_flush();

  *pva = dwLogicalAddress;

  return HVM_STATUS_SUCCESS;
}

hvm_status MmuUnmapPhysicalPage(hvm_address va, PTE entryOriginal)
{
  PPTE pentry;

  
#ifdef GUEST_WINDOWS
  pentry = (PPTE) (VIRTUAL_PT_BASE + (((VA_TO_PDE(va) ) << 12 ) |  (VA_TO_PTE(va) * sizeof(PTE))));
  
#elif defined GUEST_LINUX
  MmuVirtToPTE(va, (hvm_address*) &pentry);
#endif

  *pentry = entryOriginal;

  hvm_x86_ops.mmu_tlb_flush();
  
  return HVM_STATUS_SUCCESS;
}

hvm_status MmuReadWritePhysicalRegion(hvm_phy_address phy, void* buffer, Bit32u size, hvm_bool isWrite)
{
  hvm_status r;
  hvm_address dwLogicalAddress;
  PTE entryOriginal;

  
  if (PHY_TO_FRAME(phy) != PHY_TO_FRAME(phy+size-1)) {
      MmuPrint("[MMU] Error: physical region %.8x-%.8x crosses multiple frames\n", phy, phy+size-1);
      return HVM_STATUS_UNSUCCESSFUL;
  }
  
  r = MmuMapPhysicalPage(phy, &dwLogicalAddress, &entryOriginal);
  if (r != HVM_STATUS_SUCCESS)
    return HVM_STATUS_UNSUCCESSFUL;
  
  dwLogicalAddress += MMU_PAGE_OFFSET(phy);
  
  if (!isWrite) {
    
    MmuPrint("[MMU] MmuReadWritePhysicalRegion() Going to read %d from va: %.8x\n", size, dwLogicalAddress);
    vmm_memcpy(buffer, (Bit8u*) dwLogicalAddress, size);
    
  } else {
    
    vmm_memcpy((Bit8u*) dwLogicalAddress, buffer, size);
  }
  
  MmuPrint("[MMU] MmuReadWritePhysicalRegion() All done!\n");
  
  MmuUnmapPhysicalPage(dwLogicalAddress, entryOriginal);
  
  return HVM_STATUS_SUCCESS;
}

hvm_status MmuReadWriteVirtualRegion(hvm_address cr3, hvm_address va, void* buffer, 
				     Bit32u size, hvm_bool isWrite)
{
  hvm_status r;
  hvm_phy_address phy;
  Bit32u i, n;

  i = 0;

  MmuPrint("[MMU] MmuReadWriteVirtualRegion() cr3: %.8x va: %.8x size: %.8x isWrite? %d\n", CR3_ALIGN(cr3), va, size, isWrite);

  while (va+i < va+size) {
    n = MIN(size-i, MMU_PAGE_SIZE - MMU_PAGE_OFFSET(va+i));
    r = MmuGetPhysicalAddress(CR3_ALIGN(cr3), va+i, &phy);
    if (r != HVM_STATUS_SUCCESS)
      return HVM_STATUS_UNSUCCESSFUL;

    MmuPrint("[MMU] MmuReadWriteVirtualRegion() Reading phy %.8x (write? %d)\n", phy, isWrite);

    r = MmuReadWritePhysicalRegion(phy, (void*) ((hvm_address)buffer+i), n, isWrite);
    
    MmuPrint("[MMU] MmuReadWriteVirtualRegion() Read! Success? %d\n", (r == HVM_STATUS_SUCCESS));

    if (r != HVM_STATUS_SUCCESS)
      return HVM_STATUS_UNSUCCESSFUL;

    i += n;
  }

  MmuPrint("[MMU] MmuReadWriteVirtualRegion() done!\n");

  return HVM_STATUS_SUCCESS;;
}


hvm_status MmuGetPageEntry (hvm_address cr3, hvm_address va, PPTE ppte, hvm_bool* pisLargePage)
{
  hvm_status r;
  hvm_phy_address addr;
  PTE p;

  MmuPrint("[MMU] MmuGetPageEntry() cr3: %.8x va: %.8x\n", CR3_ALIGN(cr3), va);

#ifdef ENABLE_PAE
  
  addr = CR3_ALIGN(cr3) + (VA_TO_PDPTE(va)*sizeof(PTE));
  r = MmuReadPhysicalRegion(addr, &p, sizeof(PTE));
  if (r != HVM_STATUS_SUCCESS) {
    MmuPrint("[MMU] MmuGetPageEntry() cannot read PDPTE from %.8x\n", addr);
    return HVM_STATUS_UNSUCCESSFUL;
  }

  if (!p.Present)
    return HVM_STATUS_UNSUCCESSFUL;
  
  
  addr = FRAME_TO_PHY(p.PageBaseAddr) + (VA_TO_PDE(va)*sizeof(PTE));
#else
  
  addr = CR3_ALIGN(cr3) + (VA_TO_PDE(va)*sizeof(PTE));
#endif
  
  MmuPrint("[MMU] MmuGetPageEntry() Reading phy %.8x%.8x (NOT large)\n", GET32H(addr), GET32L(addr));
  r = MmuReadPhysicalRegion(addr, &p, sizeof(PTE));
  
  if (r != HVM_STATUS_SUCCESS) {
    MmuPrint("[MMU] MmuGetPageEntry() cannot read PDE from %.8x\n", addr);
    return HVM_STATUS_UNSUCCESSFUL;
  }
  
  MmuPrint("[MMU] MmuGetPageEntry() PDE read. Present? %d Large? %d\n", p.Present, p.LargePage);

  if (!p.Present)
    return HVM_STATUS_UNSUCCESSFUL;
  
  
  if(p.LargePage) {
    if (ppte) *ppte = p;
    *pisLargePage = TRUE;
    return HVM_STATUS_SUCCESS;
  }

  
  addr = FRAME_TO_PHY(p.PageBaseAddr) + (VA_TO_PTE(va)*sizeof(PTE));
  r = MmuReadPhysicalRegion(addr, &p, sizeof(PTE));

  if (r != HVM_STATUS_SUCCESS) {
    MmuPrint("[MMU] MmuGetPageEntry() cannot read PTE from %.8x\n", addr);
    return HVM_STATUS_UNSUCCESSFUL;
  }

  MmuPrint("[MMU] MmuGetPageEntry() PTE read. Present? %d\n", p.Present);

  if (!p.Present)
    return HVM_STATUS_UNSUCCESSFUL;
  
  if (ppte) *ppte = p;
  *pisLargePage = FALSE;
  
  return HVM_STATUS_SUCCESS;
}

#ifdef GUEST_LINUX



#ifdef ENABLE_PAE
    Bit64u dwPDE, dwPTE;
    dwPDEAddr = VIRTUAL_PD_BASE +					\
      ((VA_TO_PDE(dwCurrentAddress) | (VA_TO_PDPTE(dwCurrentAddress) << 9)) * sizeof(PTE));
#else
    Bit32u dwPDE, dwPTE;
    dwPDEAddr = VIRTUAL_PD_BASE + (VA_TO_PDE(dwCurrentAddress) * sizeof(PTE));
#endif
    
    dwPDE = READ_PTE(dwPDEAddr);
    if (!PDE_TO_VALID(dwPDE))
      continue;
    
    
    dwPTEAddr = (VIRTUAL_PT_BASE + ((( VA_TO_PDE(dwCurrentAddress) ) << 12 ) | (VA_TO_PTE(dwCurrentAddress) * sizeof(PTE))));
    dwPTE = READ_PTE(dwPTEAddr);

    if (PDE_TO_VALID(dwPTE)) {
      
      continue;
    }
    
    
    *pdwLogical = dwCurrentAddress;
    return HVM_STATUS_SUCCESS;
  }

  return HVM_STATUS_UNSUCCESSFUL;
#endif

}

static hvm_bool MmuGetCr0WP(void)
{
  CR0_REG cr0_reg;

  CR0_TO_ULONG(cr0_reg) = RegGetCr0();

  return (cr0_reg.WP != 0);
}

#if 0
static hvm_status MmuFindUnusedPDE(hvm_address* pdwLogical)
{
  hvm_address dwCurrentAddress, dwPDEAddr;

#ifdef GUEST_WINDOWS
  for (dwCurrentAddress=MMU_PAGE_SIZE; dwCurrentAddress < 0x80000000; dwCurrentAddress += MMU_PAGE_SIZE) {
    
#ifdef ENABLE_PAE
    Bit64u dwPDE;
    dwPDEAddr = VIRTUAL_PD_BASE + \
      ((VA_TO_PDE(dwCurrentAddress) | (VA_TO_PDPTE(dwCurrentAddress) << 9)) * sizeof(PTE));
#else
    Bit32u dwPDE;
    dwPDEAddr = VIRTUAL_PD_BASE + (VA_TO_PDE(dwCurrentAddress) * sizeof(PTE));
#endif

    dwPDE = READ_PTE(dwPDEAddr);
    if (PDE_TO_VALID(dwPDE)) {
      
      continue;
    }

    
    *pdwLogical = dwCurrentAddress;
    return HVM_STATUS_SUCCESS;
  }

  return HVM_STATUS_UNSUCCESSFUL;
#elif defined GUEST_LINUX
  ;
#endif
}

static void MmuPrintPDEntry(PPTE pde)
{
  ComPrint("======= PDE @ 0x%.8x =======\n", pde);
  ComPrint("Present [0x%.8x]\n", pde->Present);
  ComPrint("Writable [0x%.8x]\n", pde->Writable);
  ComPrint("Owner [0x%.8x]\n", pde->Owner);
  ComPrint("WriteThrough [0x%.8x]\n", pde->WriteThrough);
  ComPrint("CacheDisable [0x%.8x]\n", pde->CacheDisable);
  ComPrint("Accessed [0x%.8x]\n", pde->Accessed);
  ComPrint("Reserved [0x%.8x]\n", pde->Dirty);
  ComPrint("PageSize [0x%.8x]\n", pde->LargePage);
  ComPrint("Global [0x%.8x]\n", pde->Global);
  ComPrint("PTAddress [0x%.8x]\n", pde->PageBaseAddr);
}

static void MmuPrintPTEntry(PPTE pte)
{
  ComPrint("======= PTE @ 0x%.8x ======\n", pte);
  ComPrint("Present [0x%.8x]\n", pte->Present);
  ComPrint("Writable [0x%.8x]\n", pte->Writable);
  ComPrint("Owner [0x%.8x]\n", pte->Owner);
  ComPrint("WriteThrough [0x%.8x]\n", pte->WriteThrough);
  ComPrint("CacheDisable [0x%.8x]\n", pte->CacheDisable);
  ComPrint("Accessed [0x%.8x]\n", pte->Accessed);
  ComPrint("Dirty [0x%.8x]\n", pte->Dirty);
  ComPrint("PAT [0x%.8x]\n", pte->LargePage);
  ComPrint("Global [0x%.8x]\n", pte->Global);
  ComPrint("PageBaseAddress [0x%.8x]\n", pte->PageBaseAddr);
}

static void MmuPrintPageEntry(PPTE Entry)
{  
  ComPrint("%08x:%20x|%1x|%1x|%1x|%1x|%1x|%1x|%1x|%1x|%1x|%1x|%1x|%1x\n", \
	   Entry,							\
	   Entry->PageBaseAddr,						\
	   Entry->ForUse3,						\
	   Entry->ForUse2,						\
	   Entry->ForUse1,						\
	   Entry->Global,						\
	   Entry->LargePage,						\
	   Entry->Dirty,						\
	   Entry->Accessed,						\
	   Entry->CacheDisable,						\
	   Entry->WriteThrough,						\
	   Entry->Owner,						\
	   Entry->Writable,						\
	   Entry->Present						\
	   );
}
#endif
