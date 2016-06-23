
#include "extern.h"
#include "ltypes.h"
#include "input.h"


static int 
inp_buff_hook(struct ud* u)
{
  if (u->inp_buff < u->inp_buff_end)
	return *u->inp_buff++;
  else	return -1;
}

#ifndef __UD_STANDALONE__






#endif 


extern void 
ud_set_input_hook(register struct ud* u, int (*hook)(struct ud*))
{
  u->inp_hook = hook;
  inp_init(u);
}


extern void 
ud_set_input_buffer(register struct ud* u, uint8_t* buf, size_t len)
{
  u->inp_hook = inp_buff_hook;
  u->inp_buff = buf;
  u->inp_buff_end = buf + len;
  inp_init(u);
}













extern void 
ud_input_skip(struct ud* u, size_t n)
{
  while (n--) {
	u->inp_hook(u);
  }
}


extern int 
ud_input_end(struct ud* u)
{
  return (u->inp_curr == u->inp_fill) && u->inp_end;
}


extern uint8_t inp_next(struct ud* u) 
{
  int c = -1;
  
  if ( u->inp_curr != u->inp_fill ) {
	c = u->inp_cache[ ++u->inp_curr ];
  
  } else if ( u->inp_end || ( c = u->inp_hook( u ) ) == -1 ) {
	
	u->error = 1;
	
	u->inp_end = 1;
	return 0;
  } else {
	
	u->inp_curr = ++u->inp_fill;
	
	u->inp_cache[ u->inp_fill ] = (uint8_t)c;
  }
  
  u->inp_sess[ u->inp_ctr++ ] = (uint8_t)c;
  
  return ( uint8_t ) c;
}


extern void
inp_back(struct ud* u) 
{
  if ( u->inp_ctr > 0 ) {
	--u->inp_curr;
	--u->inp_ctr;
  }
}


extern uint8_t
inp_peek(struct ud* u) 
{
  uint8_t r = inp_next(u);
  if ( !u->error ) inp_back(u); 
  return r;
}


extern void
inp_move(struct ud* u, size_t n) 
{
  while (n--)
	inp_next(u);
}


extern uint8_t 
inp_uint8(struct ud* u)
{
  return inp_next(u);
}

extern uint16_t 
inp_uint16(struct ud* u)
{
  uint16_t r, ret;

  ret = inp_next(u);
  r = inp_next(u);
  return ret | (r << 8);
}

extern uint32_t 
inp_uint32(struct ud* u)
{
  uint32_t r, ret;

  ret = inp_next(u);
  r = inp_next(u);
  ret = ret | (r << 8);
  r = inp_next(u);
  ret = ret | (r << 16);
  r = inp_next(u);
  return ret | (r << 24);
}






















