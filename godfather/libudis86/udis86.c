

#ifdef GUEST_WINDOWS
#include <string.h>
#elif defined GUEST_LINUX
#include <linux/string.h>
#endif

#include "input.h"
#include "extern.h"


extern void 
ud_init(struct ud* u)
{
  memset((void*)u, 0, sizeof(struct ud));
  ud_set_mode(u, 16);
  u->mnemonic = UD_Iinvalid;
  ud_set_pc(u, 0);



}


extern unsigned int
ud_disassemble(struct ud* u)
{
  if (ud_input_end(u))
	return 0;

 
  u->insn_buffer[0] = u->insn_hexcode[0] = 0;

 
  if (ud_decode(u) == 0)
	return 0;
  if (u->translator)
	u->translator(u);
  return ud_insn_len(u);
}


extern void 
ud_set_mode(struct ud* u, uint8_t m)
{
  switch(m) {
	case 16:
	case 32:
	case 64: u->dis_mode = m ; return;
	default: u->dis_mode = 16; return;
  }
}


extern void 
ud_set_vendor(struct ud* u, unsigned v)
{
  switch(v) {
	case UD_VENDOR_INTEL:
	  u->vendor = (uint8_t)v;
		break;
	default:
		u->vendor = UD_VENDOR_AMD;
  }
}


extern void 
ud_set_pc(struct ud* u, uint64_t o)
{
  u->pc = o;
}


extern void 
ud_set_syntax(struct ud* u, void (*t)(struct ud*))
{
  u->translator = t;
}


extern char* 
ud_insn_asm(struct ud* u) 
{
  return u->insn_buffer;
}


extern uint64_t
ud_insn_off(struct ud* u) 
{
  return u->insn_offset;
}



extern char* 
ud_insn_hex(struct ud* u) 
{
  return u->insn_hexcode;
}


extern uint8_t* 
ud_insn_ptr(struct ud* u) 
{
  return u->inp_sess;
}


extern unsigned int 
ud_insn_len(struct ud* u) 
{
  return u->inp_ctr;
}
