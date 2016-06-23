


#include "types.h"
#include "debug.h"
#include "x86.h"
#include "idt.h"
#include "vmmstring.h"

#ifdef GUEST_WINDOWS
#include "winxp.h"
#endif





static hvm_status InitializeSegmentSelector(PSEGMENT_SELECTOR SegmentSelector, 
					    Bit16u Selector, Bit32u GdtBase)
{
  PSEGMENT_DESCRIPTOR2 SegDesc;

  if (!SegmentSelector)
    return HVM_STATUS_INVALID_PARAMETER;

  if (Selector & 0x4) {
    Log("InitializeSegmentSelector(): Given selector points to LDT #%.4x\n", Selector);
    return HVM_STATUS_INVALID_PARAMETER;
  }

  SegDesc = (PSEGMENT_DESCRIPTOR2) ((Bit8u*) GdtBase + (Selector & ~0x7));

  SegmentSelector->sel = Selector;
  SegmentSelector->base = SegDesc->base0 | SegDesc->base1 << 16 | SegDesc->base2 << 24;
  SegmentSelector->limit = SegDesc->limit0 | (SegDesc->limit1attr1 & 0xf) << 16;
  SegmentSelector->attributes.UCHARs = SegDesc->attr0 | (SegDesc->limit1attr1 & 0xf0) << 4;

  if (!(SegDesc->attr0 & LA_STANDARD)) {
    Bit64u tmp;
    
    tmp = (*(Bit64u*) ((Bit8u*) SegDesc + 8));
    SegmentSelector->base = (SegmentSelector->base & 0xffffffff) | (tmp << 32);
  }

  if (SegmentSelector->attributes.fields.g) {
    
    SegmentSelector->limit = (SegmentSelector->limit << 12) + 0xfff;
  }

  return HVM_STATUS_SUCCESS;
}

Bit32u GetSegmentDescriptorBase(Bit32u gdt_base, Bit16u seg_selector)
{
  Bit32u			base = 0;
  SEGMENT_DESCRIPTOR	segDescriptor = {0};
	
  vmm_memcpy(&segDescriptor, (Bit32u *)(gdt_base + (seg_selector >> 3) * 8), 8);
  base = segDescriptor.BaseHi;
  base <<= 8;
  base |= segDescriptor.BaseMid;
  base <<= 16;
  base |= segDescriptor.BaseLo;

  return base;
}

Bit32u GetSegmentDescriptorDPL(Bit32u gdt_base, Bit16u seg_selector)
{
  SEGMENT_DESCRIPTOR segDescriptor = {0};
	
  vmm_memcpy(&segDescriptor, (Bit32u *)(gdt_base + (seg_selector >> 3) * 8), 8);
	
  return segDescriptor.DPL;
}

Bit32u GetSegmentDescriptorLimit(Bit32u gdt_base, Bit16u selector)
{
  SEGMENT_SELECTOR SegmentSelector = { 0 };

  InitializeSegmentSelector(&SegmentSelector, selector, gdt_base);
	
  return SegmentSelector.limit;
}

Bit32u GetSegmentDescriptorAR(Bit32u gdt_base, Bit16u selector)
{
  SEGMENT_SELECTOR SegmentSelector = { 0 };
  Bit32u uAccessRights;

  InitializeSegmentSelector(&SegmentSelector, selector, gdt_base);

  uAccessRights = ((Bit8u*) & SegmentSelector.attributes)[0] + (((Bit8u*) & SegmentSelector.attributes)[1] << 12);
	
  if (!selector)
    uAccessRights |= 0x10000;

  return uAccessRights;
}


Bit32u RegGetIdtBase()
{
  IDTR tmp_idt;
  Bit32u inmem_base, idtr_base;
  inmem_base = 0;
  
  __asm__ __volatile__ (
			"sidt %0\n"
			:"=m"(tmp_idt)
			::"memory"
			);
  idtr_base = (tmp_idt.BaseHi << 16 | tmp_idt.BaseLo);
#ifdef GUEST_WINDOWS
  

  inmem_base = *(Bit32u*) WINDOWS_PIDT_BASE;
  if (idtr_base != inmem_base) {
    
  }
#endif 

  return inmem_base;
}
