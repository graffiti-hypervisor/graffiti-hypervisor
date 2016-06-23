






#include "hyperdbg.h"
#include "keyboard.h"
#include "scancode.h"
#include "vmmstring.h"
#include "common.h"
#include "x86.h"





#define POLL_STATUS_ITERATIONS 12000



   
#define KEYB_STATUS_OBUFFER_FULL        (1 << 0)
#define KEYB_STATUS_IBUFFER_FULL        (1 << 1)
#define KEYB_STATUS_TRANSMIT_TIMEOUT    (1 << 5)
#define KEYB_STATUS_PARITY_ERROR        (1 << 7)


#define KEYB_COMMAND_WRITE_OUTPUT      0xd2
#define KEYB_COMMAND_DISABLE_KEYBOARD  0xad
#define KEYB_COMMAND_ENABLE_KEYBOARD   0xae
#define KEYB_COMMAND_DISABLE_MOUSE     0xa7
#define KEYB_COMMAND_ENABLE_MOUSE      0xa8


#define IS_SCANCODE_RELEASE(c) (c & 0x80)
#define SCANCODE_RELEASE_FLAG  0x80






KEYBOARD_STATUS keyboard_status;





static hvm_status i8042ReadKeyboardData(Bit8u* pc, hvm_bool* pisMouse);
static hvm_bool   i8042WriteKeyboardData(Bit16u addr, Bit8u data);





static hvm_status i8042ReadKeyboardData(Bit8u* pc, hvm_bool* pisMouse)
{
  Bit8u port_status;

  port_status = IoReadPortByte(KEYB_REGISTER_STATUS);

  if (port_status & KEYB_STATUS_OBUFFER_FULL) {
    
    *pc = IoReadPortByte(KEYB_REGISTER_DATA);

    
    if ((port_status & KEYB_STATUS_PARITY_ERROR) == 0) {
      
      *pisMouse = (port_status & KEYB_STATUS_TRANSMIT_TIMEOUT) != 0;
      return HVM_STATUS_SUCCESS;
    }
  }

  return HVM_STATUS_UNSUCCESSFUL;
}

static hvm_bool i8042WriteKeyboardData(Bit16u addr, Bit8u data)
{
  Bit32u counter;

  counter = POLL_STATUS_ITERATIONS;
  while ((KEYB_STATUS_IBUFFER_FULL & IoReadPortByte(KEYB_REGISTER_STATUS)) &&
	 (counter--)) {
    CmSleep(1);
  }

  if (counter) {
    IoWritePortByte(addr, data);
    return TRUE;
  }

  return FALSE;
}


hvm_status KeyboardReadKeystroke(Bit8u* pc, hvm_bool unget, hvm_bool* pisMouse)
{
  Bit32u counter;
  Bit8u port_status, scancode;
  hvm_status r;

  counter = POLL_STATUS_ITERATIONS;
  while (counter) {
    port_status = IoReadPortByte(KEYB_REGISTER_STATUS);

    r = i8042ReadKeyboardData(&scancode, pisMouse);

    if (r == HVM_STATUS_SUCCESS) {
      break;
    }

    CmSleep(1);

    counter--;
  }

  if (counter == 0) {
    return HVM_STATUS_UNSUCCESSFUL;
  }

  if (unget) {
    
    i8042WriteKeyboardData(KEYB_REGISTER_COMMAND, KEYB_COMMAND_DISABLE_KEYBOARD);
    i8042WriteKeyboardData(KEYB_REGISTER_COMMAND, KEYB_COMMAND_WRITE_OUTPUT);
    i8042WriteKeyboardData(KEYB_REGISTER_DATA, scancode);
    i8042WriteKeyboardData(KEYB_REGISTER_COMMAND, KEYB_COMMAND_ENABLE_KEYBOARD);
  }

  *pc = scancode;

  return HVM_STATUS_SUCCESS;
}


Bit8u KeyboardScancodeToKeycode(Bit8u c)
{
  hvm_bool handled;

  handled = FALSE;

  
  switch(c & ~SCANCODE_RELEASE_FLAG) {
  case 0x1d:
    keyboard_status.lctrl = IS_SCANCODE_RELEASE(c) ? FALSE : TRUE;
    handled = TRUE;
    break;
  case 0x2a:
    keyboard_status.lshift = IS_SCANCODE_RELEASE(c) ? FALSE : TRUE;
    handled = TRUE;
    break;
  case 0x36:
    keyboard_status.rshift = IS_SCANCODE_RELEASE(c) ? FALSE : TRUE;
    handled = TRUE;
    break;
  case 0x38:
    keyboard_status.lalt = IS_SCANCODE_RELEASE(c) ? FALSE : TRUE;
    handled = TRUE;
    break;
  default:
    break;
  }

  if (handled)
    return 0;

  
  if IS_SCANCODE_RELEASE(c)
    return 0;

  
  switch(c) {
  case 0x00: 
  case 0xaa: 
  case 0xee: 
  case 0xfa: 
  case 0xfc: 
  case 0xfd: 
  case 0xfe: 
  case 0xff: 
    handled = TRUE;
  }

  if(handled)
    return 0;

  
  if((keyboard_status.lshift || keyboard_status.rshift) && scancodes_map[c] > 0x2f && scancodes_map[c] < 0x3a) {
    
    switch(scancodes_map[c]) {
    case '1':
      return (Bit8u)'!';
    case '2':
      return (Bit8u)'@';
    case '3':
      return (Bit8u)'#';
    case '4':
      return (Bit8u)'$';
    case '5':
      return (Bit8u)'%';
    case '6':
      return (Bit8u)'^';
    case '7':
      return (Bit8u)'&';
    case '8':
      return (Bit8u)'*';
    case '9':
      return (Bit8u)'(';
    case '0':
      return (Bit8u)')';
    }
  }

  if((keyboard_status.lshift || keyboard_status.rshift) && scancodes_map[c] < 0x7b && scancodes_map[c] > 0x60)
    return vmm_toupper(scancodes_map[c]);
  else
    return scancodes_map[c];
}

hvm_status KeyboardSetMouse(hvm_bool enabled)
{
  Bit8u cmd;

  cmd = enabled ? KEYB_COMMAND_ENABLE_MOUSE : KEYB_COMMAND_DISABLE_MOUSE;

  i8042WriteKeyboardData(KEYB_REGISTER_COMMAND, cmd);

  return HVM_STATUS_SUCCESS;
}

hvm_status KeyboardInit(void)
{
  init_scancodes_map();

  return HVM_STATUS_SUCCESS;
}
