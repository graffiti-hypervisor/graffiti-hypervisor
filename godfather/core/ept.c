


#include "ept.h"
#include "mmu.h"
#include "debug.h"
#include "vmmstring.h"

hvm_address VIRT_PT_BASES[HOST_GB*512]; 
INVEPT_DESCRIPTOR EPTInveptDesc;

hvm_address     Pml4;
hvm_phy_address Phys_Pml4; 


void   USESTACK EptInvept(Bit32u eptp_high, Bit32u eptp_low, Bit32u rsvd_high, Bit32u rsvd_low);

#define IA32_MTRRCAP_VCNT		0x000000ff
#define IA32_MTRRCAP_FIX		0x00000100
#define IA32_MTRRCAP_WC			0x00000400


#define PHYS_BITS_TO_MASK(bits) \
((((1ULL << (bits-1)) - 1) << 1) | 1)

static uint64_t mtrr_phys_mask;

#define IA32_MTRR_PHYMASK_VALID		0x00000800
#define IA32_MTRR_PHYSBASE_MASK		(mtrr_phys_mask & ~0x0000000000000FFFULL)
#define IA32_MTRR_PHYSBASE_TYPE		0xFF

#define MASK_TO_LEN(mask) \
((~((mask) & IA32_MTRR_PHYSBASE_MASK) & mtrr_phys_mask) + 1)

typedef struct _MTRR_FIXED_RANGE {
  hvm_address types;
} MTRR_FIXED_RANGE, *PMTRR_FIXED_RANGE;

typedef struct _MTRR_RANGE {
  hvm_address base;
  Bit64u size;
  Bit8u type;
  
} MTRR_RANGE, *PMTRR_RANGE;

#define MAX_SUPPORTED_MTRR_RANGE 32
#define MAX_SUPPORTED_MTRR_FIXED_RANGE 12

MTRR_RANGE ranges[MAX_SUPPORTED_MTRR_RANGE];
MTRR_FIXED_RANGE fixed_ranges[MAX_SUPPORTED_MTRR_FIXED_RANGE];

void EPTInit()
{
  unsigned long long count = 0;
  unsigned int i, n;
  MSR base, mask;

	
	
	
	
	
  __asm__ __volatile__ ("pushl %%eax\n"
                        "pushl %%ebx\n"
                        "pushl %%ecx\n"
                        "pushl %%edx\n"
                        "movl $0x80000008, %%eax\n"
                        "cpuid\n"
                        "movl %%eax, %0\n"
                        "popl %%edx\n"
                        "popl %%ecx\n"
                        "popl %%ebx\n"
                        "popl %%eax\n"
                        :"=m"(n)
                        ::
                        );

  n &= 0xff;
  mtrr_phys_mask = PHYS_BITS_TO_MASK(n);

  vmm_memset(ranges, 0, MAX_SUPPORTED_MTRR_RANGE*sizeof(MTRR_RANGE));
  vmm_memset(fixed_ranges, 0, MAX_SUPPORTED_MTRR_RANGE*sizeof(MTRR_FIXED_RANGE));

  ReadMSR(MSR_IA32_MTRRCAP, &base);
  count = ((((unsigned long long) base.Hi) << 32) | base.Lo) & IA32_MTRRCAP_VCNT;
  for(i = 0; i < count; i++) {
    ReadMSR(MSR_IA32_MTRR_PHYSBASE(i), &base);
    ReadMSR(MSR_IA32_MTRR_PHYSMASK(i), &mask);
    if(i >= MAX_SUPPORTED_MTRR_RANGE) {
      GuestLog("PANIC! Not enough space for mtrr ranges!!!");
      __asm__ __volatile__ ("ud2");
    }
    if(mask.Lo & IA32_MTRR_PHYMASK_VALID) {
      ranges[i].base = base.Lo & IA32_MTRR_PHYSBASE_MASK;
      ranges[i].size = MASK_TO_LEN((((unsigned long long) mask.Hi) << 32) | mask.Lo);
      ranges[i].type = (Bit8u) (base.Lo & IA32_MTRR_PHYSBASE_TYPE);
    }
  }
  
  i = 0;
  ReadMSR(MSR_IA32_MTRR_FIX64K_00000, &base);
  fixed_ranges[i++].types = base.Lo;
  ReadMSR(MSR_IA32_MTRR_FIX16K_80000, &base);
  fixed_ranges[i++].types = base.Lo;
  ReadMSR(MSR_IA32_MTRR_FIX16K_A0000, &base);
  fixed_ranges[i++].types = base.Lo;
  ReadMSR(MSR_IA32_MTRR_FIX4K_C0000, &base);
  fixed_ranges[i++].types = base.Lo;
  ReadMSR(MSR_IA32_MTRR_FIX4K_C8000, &base);
  fixed_ranges[i++].types = base.Lo;
  ReadMSR(MSR_IA32_MTRR_FIX4K_D0000, &base);
  fixed_ranges[i++].types = base.Lo;
  ReadMSR(MSR_IA32_MTRR_FIX4K_D8000, &base);
  fixed_ranges[i++].types = base.Lo;
  ReadMSR(MSR_IA32_MTRR_FIX4K_E0000, &base);
  fixed_ranges[i++].types = base.Lo;
  ReadMSR(MSR_IA32_MTRR_FIX4K_E8000, &base);
  fixed_ranges[i++].types = base.Lo;
  ReadMSR(MSR_IA32_MTRR_FIX4K_F0000, &base);
  fixed_ranges[i++].types = base.Lo;
  ReadMSR(MSR_IA32_MTRR_FIX4K_F8000, &base);
  fixed_ranges[i++].types = base.Lo;
}

Bit8u EPTGetMemoryType(hvm_address address)
{
  Bit8u type = 0, index;
  if(address < 0x100000) { 
    if(address < 0x80000) { 
      type = (fixed_ranges[0].types & (0xff << ((address >> 16) * 8))) >> ((address >> 16) * 8);
    }
    else if (address < 0xa0000){
      address -= 0x80000;
      type = (fixed_ranges[1].types & (0xff << ((address >> 14) * 8))) >> ((address >> 14) * 8);
    }
    else if (address < 0xc0000) {
      address -= 0xa0000;
      type = (fixed_ranges[2].types & (0xff << ((address >> 14) * 8))) >> ((address >> 14) * 8);
    }
    else {
      index = ((address - 0xc0000) >> 15) + 3;
      address &= 0x7fff;
      type = (fixed_ranges[index].types & (0xff << ((address >> 12) * 8))) >> ((address >> 12) * 8);
    }
  }
  else {
    index = 0;
    while (index < MAX_SUPPORTED_MTRR_RANGE) {
      if(ranges[index].base <= address && (ranges[index].base+ranges[index].size) > address) {
        return ranges[index].type;
      }
      index++;
    }
    type = MEM_TYPE_WRITEBACK;
  }

  
  

  return type;
}

void EPTAlterPT(hvm_address guest_phy, Bit8u perms, hvm_bool isRemove)
{
  Bit32u entryNum, offset;
  Bit32u pdpte_num, pde_num, pte_num;
  hvm_address pte_low, pte_high = 0, va_of_pte;

	
  entryNum = guest_phy & 0xc0000000;
  entryNum = entryNum >> 30;
  pdpte_num = entryNum;

	
  entryNum = guest_phy & 0x3fe00000;
  entryNum = entryNum >> 21;
  pde_num = entryNum;
  
	
  entryNum = guest_phy & 0x001ff000;
  entryNum = entryNum >> 12;
  pte_num = entryNum;
  offset   = entryNum*8;

	
  va_of_pte = VIRT_PT_BASES[(pdpte_num*512)+pde_num] + (pte_num * 8);

  if(isRemove) {
    pte_low = *((hvm_address *)va_of_pte);
    pte_low = (pte_low | (EPTGetMemoryType(pte_low & 0xfffff000) << 3)) & ~perms;
  }
  else {
    pte_low = (guest_phy & 0xfffff000) | (EPTGetMemoryType(guest_phy & 0xfffff000) << 3) | perms;
  }

	
  *((hvm_address *)va_of_pte) = pte_low;
  *((hvm_address *)(va_of_pte+4)) = pte_high;

  
  EptInvept(GET32H(EPTInveptDesc.Eptp), GET32L(EPTInveptDesc.Eptp), GET32H(EPTInveptDesc.Rsvd), GET32L(EPTInveptDesc.Rsvd));
}

hvm_address EPTGetEntry(hvm_address guest_phy) 
{
  Bit32u entryNum, offset;
  Bit32u pdpte_num, pde_num, pte_num;
  hvm_address va_of_pte;

	
  entryNum = guest_phy & 0xc0000000;
  entryNum = entryNum >> 30;
  pdpte_num = entryNum;

	
  entryNum = guest_phy & 0x3fe00000;
  entryNum = entryNum >> 21;
  pde_num = entryNum;
  
	
  entryNum = guest_phy & 0x001ff000;
  entryNum = entryNum >> 12;
  pte_num = entryNum;
  offset   = entryNum*8;

	
  va_of_pte = VIRT_PT_BASES[(pdpte_num*512)+pde_num] + (pte_num * 8);
	
	return va_of_pte;
}


void EPTProtectPhysicalRange(hvm_address base, Bit32u size, Bit8u permsToRemove) {

  hvm_phy_address phyaddr;
  hvm_address i;

  for(i = base; i < base+size; i=i+4096) {
    MmuGetPhysicalAddress(RegGetCr3(), i, &phyaddr);
    EPTRemovePTperms(GET32L(phyaddr), permsToRemove);
  }
}







  

























  


















