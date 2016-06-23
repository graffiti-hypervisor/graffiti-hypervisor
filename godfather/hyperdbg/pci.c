


#include "types.h"
#include "debug.h"
#include "x86.h"





#define PCI_CONF_TYPE_NONE 0
#define PCI_CONF_TYPE_1    1
#define PCI_CONF_TYPE_2    2


#define PCI_VENDOR_ID           0x00        
#define PCI_DEVICE_ID           0x02        
#define PCI_COMMAND             0x04        
#define PCI_STATUS              0x06        
#define PCI_REVISION            0x08        
#define PCI_CLASS_API           0x09        
#define PCI_CLASS_SUB           0x0a        
#define PCI_CLASS_BASE          0x0b        
#define PCI_LINE_SIZE           0x0c        
#define PCI_LATENCY             0x0d        
#define PCI_HEADER_TYPE         0x0e        
#define PCI_BIST                0x0f        


#define PCI_HEADER_TYPE_NORMAL   0x00
#define PCI_HEADER_TYPE_BRIDGE   0x01
#define PCI_HEADER_TYPE_CARDBUS  0x02


#define PCI_BASE_ADDRESS_SPACE_MEMORY   0x00
#define PCI_BASE_ADDRESS_MEM_TYPE_32	0x00	
#define PCI_BASE_ADDRESS_SPACE	        0x01	
#define PCI_BASE_ADDRESS_SPACE_IO       0x01
#define PCI_BASE_ADDRESS_MEM_TYPE_1M	0x02	
#define PCI_BASE_ADDRESS_MEM_TYPE_64	0x04	
#define PCI_BASE_ADDRESS_MEM_TYPE_MASK  0x06
#define PCI_BASE_ADDRESS_MEM_PREFETCH	0x08	
#define PCI_BASE_ADDRESS_0	        0x10	
#define PCI_BASE_ADDRESS_1	        0x14	
#define PCI_BASE_ADDRESS_2	        0x18	
#define PCI_BASE_ADDRESS_3	        0x1c	
#define PCI_BASE_ADDRESS_4	        0x20	
#define PCI_BASE_ADDRESS_5	        0x24	
#define PCI_BASE_ADDRESS_MEM_MASK	(~0x0fUL)
#define PCI_BASE_ADDRESS_IO_MASK	(~0x03UL)

#define PCI_CONF1_ADDRESS(bus, dev, fn, reg)				\
  (0x80000000 | (bus << 16) | (dev << 11) | (fn << 8) | (reg & ~3))

#define PCI_CONF2_ADDRESS(dev, reg)	(unsigned short)(0xC000 | (dev << 8) | reg)





struct pci_desc {
  unsigned int id;
  unsigned char name[130];
  struct pci_desc* list;
};
typedef struct pci_desc pci_desc;

typedef struct pci_info {
    Bit16u  vendor_id;              
    Bit16u  device_id;              
    Bit16u  command;                
    Bit16u  status;                 
    Bit8u   revision;               
    Bit8u   class_api;              
    Bit8u   class_sub;              
    Bit8u   class_base;             
    Bit8u   line_size;              
    Bit8u   latency;                
    Bit8u   header_type;            
    Bit8u   bist;                   

    union {
        struct {
	  
            Bit32u  base_registers[6];      
	    Bit32u  cardbus_cis;            

            Bit16u  subsystem_vendor_id;    
            Bit16u  subsystem_id;           

	  
	    Bit32u   rom_base;               
            Bit32u   rom_base_pci;           
            Bit32u   rom_size;               

	  
            Bit8u   interrupt_line;         
            Bit8u   interrupt_pin;          

	  
	    Bit8u   min_grant;              
            Bit8u   max_latency;            
        } h0;

        struct {
	  
            Bit32u  base_registers[2];      

            Bit32u  base_registers_pci[2];  
            Bit32u  base_register_sizes[2]; 
            Bit8u   base_register_flags[2]; 

            Bit8u   primary_bus;
            Bit8u   secondary_bus;
            Bit8u   subordinate_bus;
            Bit8u   secondary_latency;
            Bit8u   io_base;
            Bit8u   io_limit;
            Bit16u  secondary_status;
            Bit16u  memory_base;
            Bit16u  memory_limit;
            Bit16u  prefetchable_memory_base;
            Bit16u  prefetchable_memory_limit;
            Bit32u  prefetchable_memory_base_upper32;
            Bit32u  prefetchable_memory_limit_upper32;

	  
            Bit16u  io_base_upper16;
            Bit16u  io_limit_upper16;
            Bit32u  rom_base;               
	    Bit32u  rom_base_pci;           
	    
	  
	    Bit8u   interrupt_line;         
            Bit8u   interrupt_pin;          
            Bit16u  bridge_control;     
        } h1; 
    } u;
} pci_info;





static Bit8u pci_conf_type = PCI_CONF_TYPE_NONE;





static int   PCIConfRead(unsigned bus, unsigned dev, unsigned fn, unsigned reg, unsigned len, unsigned int *value);

#if 0
static void   PCIListController(void);
static Bit32u PCIGetName(unsigned int v, unsigned int d, unsigned char *out_char, int out_size);
#endif



	if (p_pci_info->class_base != 3)
	  continue;

	if (header_type_tmp == PCI_HEADER_TYPE_NORMAL) {
	  int i;
	  for (i=0; i<sizeof(p_pci_info->u.h0.base_registers)/sizeof(Bit32u); i++) {
	    Bit32u pos, flg, j;
	    
	    pos = p_pci_info->u.h0.base_registers[i];
	    j = PCI_BASE_ADDRESS_0 + 4*i;
	    flg = pci_data[j] | (pci_data[j+1] << 8) | (pci_data[j+2] << 16) | (pci_data[j+3] << 24);
	    if (flg == 0xffffffff)
	      flg = 0;
	    if (!pos && !flg)
	      continue;
	    if (!(flg & PCI_BASE_ADDRESS_SPACE_IO) && (flg & PCI_BASE_ADDRESS_MEM_PREFETCH)) {
	      GuestLog("[D] Prefetchable PCI memory at %.8x\n",(Bit32u) (pos & PCI_BASE_ADDRESS_MEM_MASK));
	      *pdisplay_address = pos & PCI_BASE_ADDRESS_MEM_MASK;
	      break;
	    }
	  }
	} else if (header_type_tmp == PCI_HEADER_TYPE_BRIDGE) {
	  *pdisplay_address = p_pci_info->u.h1.base_registers[1];
	  *pdisplay_address &= ~PCI_BASE_ADDRESS_SPACE_IO;
	  *pdisplay_address &= PCI_BASE_ADDRESS_MEM_MASK;
	} else {
	  GuestLog("[W] Unexpected PCI header\n");
	  continue;
	}

#if 0
	PCIGetName(vendor, device, debug, sizeof(debug));
	GuestLog("[*] Good device '%s'\n", debug);
#endif

	return HVM_STATUS_SUCCESS;
      }

  GuestLog("[E] PCI scan: failed\n");

  return HVM_STATUS_UNSUCCESSFUL;
}

#if 0
static void PCIListController(void)
{
  int i, result;
  unsigned int ctrl_bus, ctrl_dev, ctrl_fn, tmp, vendor, device;
  unsigned char pci_data[0x40];
 
  for (ctrl_bus=0; ctrl_bus<255; ctrl_bus++)
    for (ctrl_dev=0; ctrl_dev<31; ctrl_dev++)
      for (ctrl_fn=0; ctrl_fn<7; ctrl_fn++) {
	result = PCIConfRead(ctrl_bus, ctrl_dev, ctrl_fn, PCI_VENDOR_ID, 2, &vendor);
	result = PCIConfRead(ctrl_bus, ctrl_dev, ctrl_fn, PCI_DEVICE_ID, 2, &device);
	  
	if ((vendor == 0xffff || device == 0xffff ) ||
	    (vendor == 0x0 && device == 0x0))
	  continue;

	for (i=0;i<0x40;i++) {
	  result = PCIConfRead(ctrl_bus, ctrl_dev, ctrl_fn, i,1, &tmp);
	  pci_data[i] = (unsigned char)(tmp & 0xff);
	}
      }
}

static Bit32u PCIGetName(unsigned int v, unsigned int d, unsigned char *out_char, int out_size)
{
  unsigned int i, ii;
  pci_desc* vendor;
  pci_desc* device;
  Bit32u precision = 0;

  for(i=0; i<sizeof(tab_vendor)/sizeof(pci_desc); i++) {
      vendor=&tab_vendor[i];
      if (vendor->id != v)
	continue;

      RtlStringCbCopyA(out_char, out_size, vendor->name);
      RtlStringCbCatA(out_char, out_size, " ");
      precision=1;
      if (vendor->list == NULL)
	continue;

      for(ii=0;;ii++) {
	device = &(vendor->list[ii]);
	if (device->id == 0)
	  break;

	if (device->id == d)
	  RtlStringCbCatA(out_char, out_size, device->name);
      }

      precision=2;
      return precision;
    }

  return precision;
}
#endif

