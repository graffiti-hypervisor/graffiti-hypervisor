




#include "comio.h"
#include "debug.h"
#include "common.h"
#include "vmmstring.h"
#include "x86.h"

#define TRANSMIT_HOLDING_REGISTER	   0x00
#define RECEIVER_BUFFER_REGISTER           0x00
#define INTERRUPT_ENABLE_REGISTER          0x01
#define INTERRUPT_IDENTIFICATION_REGISTER  0x02
#define LINE_STATUS_REGISTER		   0x05


#define LSR_DATA_AVAILABLE              (1 << 0)
#define LSR_OVERRUN_ERROR               (1 << 1)
#define LSR_PARITY_ERROR                (1 << 2)
#define LSR_FRAMING_ERROR               (1 << 3)
#define LSR_BREAK_SIGNAL                (1 << 4)
#define LSR_THR_EMPTY                   (1 << 5)
#define LSR_THR_EMPTY_AND_IDLE          (1 << 6)
#define LSR_ERR_DATA                    (1 << 7)


#define IER_RECEIVED_DATA               (1 << 0)
#define IER_TRANSMITTER_EMPTY           (1 << 1)
#define IER_RECEIVER_CHANGED            (1 << 2)
#define IER_MODEM_CHANGED               (1 << 3)
#define IER_SLEEP_MODE                  (1 << 4)
#define IER_LOW_POWER_MODE              (1 << 5)
#define IER_RESERVED1                   (1 << 6)
#define IER_RESERVED2                   (1 << 7)


static Bit16u  DebugComPort = 0;
static Bit32u  ComSpinLock;	

void ComInit()
{
#ifdef GUEST_LINUX
  
  
  IoWritePortByte(DebugComPort + 1, 0x00);    
  IoWritePortByte(DebugComPort + 3, 0x80);    
  IoWritePortByte(DebugComPort + 0, 0x03);    
  IoWritePortByte(DebugComPort + 1, 0x00);    
  IoWritePortByte(DebugComPort + 3, 0x03);    
  IoWritePortByte(DebugComPort + 2, 0xC7);    
  IoWritePortByte(DebugComPort + 4, 0x0B);    
#else
#warning "Windows serial support is currently not working properly in VmWare Workstation 8"
#endif

  CmInitSpinLock(&ComSpinLock);

 }

void ComPrint(const char* fmt, ...)
{
  va_list args;
  char str[1024] = {0};
  unsigned int i;

  CmAcquireSpinLock(&ComSpinLock);
  
  va_start(args, fmt);
  vmm_vsnprintf(str, sizeof(str), fmt, args);
  va_end(args);  
  for (i = 0; i < vmm_strlen(str); i++)
    PortSendByte(str[i]);
  CmReleaseSpinLock(&ComSpinLock);
}

Bit8u ComIsInitialized()
{
  
  return (DebugComPort != 0);
}

void PortInit()
{
  DebugComPort = COM_PORT_ADDRESS;
}

void PortSendByte(Bit8u b)
{
  
  while (!(IoReadPortByte(DebugComPort + LINE_STATUS_REGISTER) & LSR_THR_EMPTY));
  
  IoWritePortByte(DebugComPort + TRANSMIT_HOLDING_REGISTER, b);
}

Bit8u PortRecvByte(void)
{
  
  while ((IoReadPortByte(DebugComPort + LINE_STATUS_REGISTER) & LSR_DATA_AVAILABLE) == 0);
  
  return IoReadPortByte(DebugComPort + RECEIVER_BUFFER_REGISTER);
}
