




#include "ltypes.h"
#include "itab.h"
#include "input.h"
#include "decode.h"
#include "vmmstring.h"


#define MAX_PREFIXES    15

static struct ud_itab_entry ie_invalid = { UD_Iinvalid, O_NONE, O_NONE, O_NONE, P_none };
static struct ud_itab_entry ie_pause   = { UD_Ipause,   O_NONE, O_NONE, O_NONE, P_none };
static struct ud_itab_entry ie_nop     = { UD_Inop,     O_NONE, O_NONE, O_NONE, P_none };



const char * ud_lookup_mnemonic( enum ud_mnemonic_code c )
{
    if ( c < UD_Id3vil )
        return ud_mnemonics_str[ c ];
    return NULL;
}



static int get_prefixes( struct ud* u )
{
    unsigned int have_pfx = 1;
    unsigned int i;
    uint8_t curr;

    
    if ( u->error ) 
        return -1; 

    
    for ( i = 0; have_pfx ; ++i ) {

        
        inp_next(u); 
        if ( u->error ) 
            return -1;
        curr = inp_curr( u );

        
        if ( u->dis_mode == 64 && ( curr & 0xF0 ) == 0x40 ) {
            u->pfx_rex = curr;  
        } else {
            switch ( curr )  
            {
            case 0x2E : 
                u->pfx_seg = UD_R_CS; 
                u->pfx_rex = 0;
                break;
            case 0x36 :     
                u->pfx_seg = UD_R_SS; 
                u->pfx_rex = 0;
                break;
            case 0x3E : 
                u->pfx_seg = UD_R_DS; 
                u->pfx_rex = 0;
                break;
            case 0x26 : 
                u->pfx_seg = UD_R_ES; 
                u->pfx_rex = 0;
                break;
            case 0x64 : 
                u->pfx_seg = UD_R_FS; 
                u->pfx_rex = 0;
                break;
            case 0x65 : 
                u->pfx_seg = UD_R_GS; 
                u->pfx_rex = 0;
                break;
            case 0x67 :  
                u->pfx_adr = 0x67;
                u->pfx_rex = 0;
                break;
            case 0xF0 : 
                u->pfx_lock = 0xF0;
                u->pfx_rex  = 0;
                break;
            case 0x66: 
                
                if ( !u->pfx_insn ) u->pfx_insn = 0x66;
                u->pfx_opr = 0x66;           
                u->pfx_rex = 0;
                break;
            case 0xF2:
                u->pfx_insn  = 0xF2;
                u->pfx_repne = 0xF2; 
                u->pfx_rex   = 0;
                break;
            case 0xF3:
                u->pfx_insn = 0xF3;
                u->pfx_rep  = 0xF3; 
                u->pfx_repe = 0xF3; 
                u->pfx_rex  = 0;
                break;
            default : 
                
                have_pfx = 0;
                break;
            }
        }

        
        if ( i + 1 == MAX_INSN_LENGTH ) {
            u->error = 1;
            break;
        }
    }

    
    if ( u->error ) 
        return -1; 

    
    inp_back(u);

    
    if ( u->dis_mode == 64 ) {
        u->opr_mode = REX_W( u->pfx_rex ) ? 64 : ( ( u->pfx_opr ) ? 16 : 32 ) ;
        u->adr_mode = ( u->pfx_adr ) ? 32 : 64;
    } else if ( u->dis_mode == 32 ) {
        u->opr_mode = ( u->pfx_opr ) ? 16 : 32;
        u->adr_mode = ( u->pfx_adr ) ? 16 : 32;
    } else if ( u->dis_mode == 16 ) {
        u->opr_mode = ( u->pfx_opr ) ? 32 : 16;
        u->adr_mode = ( u->pfx_adr ) ? 32 : 16;
    }

    return 0;
}



static int search_itab( struct ud * u )
{
    struct ud_itab_entry * e = NULL;
    enum ud_itab_index table;
    uint8_t peek;
    uint8_t did_peek = 0;
    uint8_t curr; 
    uint8_t index;

    
    if ( u->error ) 
        return -1;

    
    inp_next(u); 
    if ( u->error ) 
        return -1;
    curr = inp_curr(u); 

    
    if ( 0x90 == curr ) {
        if ( !( u->dis_mode == 64 && REX_B( u->pfx_rex ) ) ) {
            if ( u->pfx_rep ) {
                u->pfx_rep = 0;
                e = & ie_pause;
            } else {
                e = & ie_nop;
            }
            goto found_entry;
        }
    }

    
    if ( 0x0F == curr ) {
        table = ITAB__0F;
        curr  = inp_next(u);
        if ( u->error )
            return -1;

        
        if ( 0x66 == u->pfx_insn ) {
            if ( ud_itab_list[ ITAB__PFX_SSE66__0F ][ curr ].mnemonic != UD_Iinvalid ) {
                table = ITAB__PFX_SSE66__0F;
                u->pfx_opr = 0;
            }
        } else if ( 0xF2 == u->pfx_insn ) {
            if ( ud_itab_list[ ITAB__PFX_SSEF2__0F ][ curr ].mnemonic != UD_Iinvalid ) {
                table = ITAB__PFX_SSEF2__0F; 
                u->pfx_repne = 0;
            }
        } else if ( 0xF3 == u->pfx_insn ) {
            if ( ud_itab_list[ ITAB__PFX_SSEF3__0F ][ curr ].mnemonic != UD_Iinvalid ) {
                table = ITAB__PFX_SSEF3__0F;
                u->pfx_repe = 0;
                u->pfx_rep  = 0;
            }
        }
    
    } else {
        table = ITAB__1BYTE; 
    }

    index = curr;

search:

    e = & ud_itab_list[ table ][ index ];

    
    
    if ( e->mnemonic < UD_Id3vil ) {
        if ( e->mnemonic == UD_Iinvalid ) {
            if ( did_peek ) {
                inp_next( u ); if ( u->error ) return -1;
            }
            goto found_entry;
        }
        goto found_entry;
    }

    table = e->prefix;

    switch ( e->mnemonic )
    {
    case UD_Igrp_reg:
        peek     = inp_peek( u );
        did_peek = 1;
        index    = MODRM_REG( peek );
        break;

    case UD_Igrp_mod:
        peek     = inp_peek( u );
        did_peek = 1;
        index    = MODRM_MOD( peek );
        if ( index == 3 )
           index = ITAB__MOD_INDX__11;
        else 
           index = ITAB__MOD_INDX__NOT_11; 
        break;

    case UD_Igrp_rm:
        curr     = inp_next( u );
        did_peek = 0;
        if ( u->error )
            return -1;
        index    = MODRM_RM( curr );
        break;

    case UD_Igrp_x87:
        curr     = inp_next( u );
        did_peek = 0;
        if ( u->error )
            return -1;
        index    = curr - 0xC0;
        break;

    case UD_Igrp_osize:
        if ( u->opr_mode == 64 ) 
            index = ITAB__MODE_INDX__64;
        else if ( u->opr_mode == 32 ) 
            index = ITAB__MODE_INDX__32;
        else
            index = ITAB__MODE_INDX__16;
        break;
 
    case UD_Igrp_asize:
        if ( u->adr_mode == 64 ) 
            index = ITAB__MODE_INDX__64;
        else if ( u->adr_mode == 32 ) 
            index = ITAB__MODE_INDX__32;
        else
            index = ITAB__MODE_INDX__16;
        break;               

    case UD_Igrp_mode:
        if ( u->dis_mode == 64 ) 
            index = ITAB__MODE_INDX__64;
        else if ( u->dis_mode == 32 ) 
            index = ITAB__MODE_INDX__32;
        else
            index = ITAB__MODE_INDX__16;
        break;

    case UD_Igrp_vendor:
        if ( u->vendor == UD_VENDOR_INTEL ) 
            index = ITAB__VENDOR_INDX__INTEL; 
        else if ( u->vendor == UD_VENDOR_AMD )
            index = ITAB__VENDOR_INDX__AMD;


        break;

    case UD_Id3vil:

        break;

    default:

        break;
    }

    goto search;

found_entry:

    u->itab_entry = e;
    u->mnemonic = u->itab_entry->mnemonic;

    return 0;
}


static unsigned int resolve_operand_size( const struct ud * u, unsigned int s )
{
    switch ( s ) 
    {
    case SZ_V:
        return ( u->opr_mode );
    case SZ_Z:  
        return ( u->opr_mode == 16 ) ? 16 : 32;
    case SZ_P:  
        return ( u->opr_mode == 16 ) ? SZ_WP : SZ_DP;
    case SZ_MDQ:
        return ( u->opr_mode == 16 ) ? 32 : u->opr_mode;
    case SZ_RDQ:
        return ( u->dis_mode == 64 ) ? 64 : 32;
    default:
        return s;
    }
}


static int resolve_mnemonic( struct ud* u )
{
  
  u->br_far = 0;
  u->br_near = 0;
  
  if ( u->mnemonic == UD_Icall || u->mnemonic == UD_Ijmp ) {
    
    if ( u->operand[ 0 ].size == SZ_WP ) {
        u->operand[ 0 ].size = 16;
        u->br_far = 1;
        u->br_near= 0;
    
    } else if ( u->operand[ 0 ].size == SZ_DP ) {
        u->operand[ 0 ].size = 32;
        u->br_far = 1;
        u->br_near= 0;
    } else {
        u->br_far = 0;
        u->br_near= 1;
    }
  
  } else if ( u->mnemonic == UD_I3dnow ) {
    u->mnemonic = ud_itab_list[ ITAB__3DNOW ][ inp_curr( u )  ].mnemonic;
  }
  
  if ( u->mnemonic == UD_Iswapgs && u->dis_mode != 64 ) {
    u->error = 1;
    return -1;
  }

  return 0;
}



static void 
decode_a(struct ud* u, struct ud_operand *op)
{
  if (u->opr_mode == 16) {  
    
    op->type = UD_OP_PTR;
    op->size = 32;
    op->lval.ptr.off = inp_uint16(u);
    op->lval.ptr.seg = inp_uint16(u);
  } else {
    
    op->type = UD_OP_PTR;
    op->size = 48;
    op->lval.ptr.off = inp_uint32(u);
    op->lval.ptr.seg = inp_uint16(u);
  }
}


static enum ud_type 
decode_gpr(register struct ud* u, unsigned int s, unsigned char rm)
{
  s = resolve_operand_size(u, s);
        
  switch (s) {
    case SZ_DP:
    case 32:
        return UD_R_EAX + rm;
    case SZ_WP:
    case 16:
        return UD_R_AX  + rm;
    case  8:
        if (u->dis_mode == 64 && u->pfx_rex) {
            if (rm >= 4)
                return UD_R_SPL + (rm-4);
            return UD_R_AL + rm;
        } else return UD_R_AL + rm;
    default:
        return 0;
  }
}


static enum ud_type 
resolve_gpr64(struct ud* u, enum ud_operand_code gpr_op)
{
  if (gpr_op >= OP_rAXr8 && gpr_op <= OP_rDIr15)
    gpr_op = (gpr_op - OP_rAXr8) | (REX_B(u->pfx_rex) << 3);          
  else  gpr_op = (gpr_op - OP_rAX);

  if (u->opr_mode == 16)
    return gpr_op + UD_R_AX;
  if (u->dis_mode == 32 || 
    (u->opr_mode == 32 && ! (REX_W(u->pfx_rex) || u->default64))) {
    return gpr_op + UD_R_EAX;
  }

  return gpr_op + UD_R_RAX;
}


static enum ud_type 
resolve_gpr32(struct ud* u, enum ud_operand_code gpr_op)
{
  gpr_op = gpr_op - OP_eAX;

  if (u->opr_mode == 16) 
    return gpr_op + UD_R_AX;

  return gpr_op +  UD_R_EAX;
}


static enum ud_type 
resolve_reg(struct ud* u, unsigned int type, unsigned char i)
{
  switch (type) {
    case T_MMX :    return UD_R_MM0  + (i & 7);
    case T_XMM :    return UD_R_XMM0 + i;
    case T_CRG :    return UD_R_CR0  + i;
    case T_DBG :    return UD_R_DR0  + i;
    case T_SEG :    return UD_R_ES   + (i & 7);
    case T_NONE:
    default:    return UD_NONE;
  }
}


static void 
decode_imm(struct ud* u, unsigned int s, struct ud_operand *op)
{
  op->size = (uint8_t) resolve_operand_size(u, s);
  op->type = UD_OP_IMM;

  switch (op->size) {
    case  8: op->lval.sbyte = inp_uint8(u);   break;
    case 16: op->lval.uword = inp_uint16(u);  break;
    case 32: op->lval.udword = inp_uint32(u); break;
    default: return;
  }
}


static void 
decode_modrm(struct ud* u, struct ud_operand *op, unsigned int s, 
         unsigned char rm_type, struct ud_operand *opreg, 
			 unsigned int reg_size, unsigned char reg_type)
{
  unsigned char mod, rm, reg;

  inp_next(u);

  
  mod = MODRM_MOD(inp_curr(u));
  rm  = (REX_B(u->pfx_rex) << 3) | MODRM_RM(inp_curr(u));
  reg = (REX_R(u->pfx_rex) << 3) | MODRM_REG(inp_curr(u));

  op->size = (uint8_t) resolve_operand_size(u, s);

  
  if (mod == 3) {
    op->type = UD_OP_REG;
    if (rm_type ==  T_GPR)
        op->base = decode_gpr(u, op->size, rm);
    else    op->base = resolve_reg(u, rm_type, (REX_B(u->pfx_rex) << 3) | (rm&7));
  } 
    
  else {
    op->type = UD_OP_MEM;

    
    if (u->adr_mode == 64) {

        op->base = UD_R_RAX + rm;

        
        if (mod == 1)
            op->offset = 8;
        else if (mod == 2)
            op->offset = 32;
        else if (mod == 0 && (rm & 7) == 5) {           
            op->base = UD_R_RIP;
            op->offset = 32;
        } else  op->offset = 0;

        
        if ((rm & 7) == 4) {
            inp_next(u);
            
            op->scale = (1 << SIB_S(inp_curr(u))) & ~1;
            op->index = UD_R_RAX + (SIB_I(inp_curr(u)) | (REX_X(u->pfx_rex) << 3));
            op->base  = UD_R_RAX + (SIB_B(inp_curr(u)) | (REX_B(u->pfx_rex) << 3));

            
            if (op->index == UD_R_RSP) {
                op->index = UD_NONE;
                op->scale = UD_NONE;
            }

            if (op->base == UD_R_RBP || op->base == UD_R_R13) {
                if (mod == 0) 
                    op->base = UD_NONE;
                if (mod == 1)
                    op->offset = 8;
                else op->offset = 32;
            }
        }
    } 

    
    else if (u->adr_mode == 32) {

        
        op->base = UD_R_EAX + rm;

        
        if (mod == 1)
            op->offset = 8;
        else if (mod == 2)
            op->offset = 32;
        else if (mod == 0 && rm == 5) {
            op->base = UD_NONE;
            op->offset = 32;
        } else  op->offset = 0;

        
        if ((rm & 7) == 4) {
            inp_next(u);

            op->scale = (1 << SIB_S(inp_curr(u))) & ~1;
            op->index = UD_R_EAX + (SIB_I(inp_curr(u)) | (REX_X(u->pfx_rex) << 3));
            op->base  = UD_R_EAX + (SIB_B(inp_curr(u)) | (REX_B(u->pfx_rex) << 3));

            if (op->index == UD_R_ESP) {
                op->index = UD_NONE;
                op->scale = UD_NONE;
            }

            
            if (op->base == UD_R_EBP) {
                if (mod == 0)
                    op->base = UD_NONE;
                if (mod == 1)
                    op->offset = 8;
                else op->offset = 32;
            }
        }
    } 

    
    else  {
        switch (rm) {
            case 0: op->base = UD_R_BX; op->index = UD_R_SI; break;
            case 1: op->base = UD_R_BX; op->index = UD_R_DI; break;
            case 2: op->base = UD_R_BP; op->index = UD_R_SI; break;
            case 3: op->base = UD_R_BP; op->index = UD_R_DI; break;
            case 4: op->base = UD_R_SI; break;
            case 5: op->base = UD_R_DI; break;
            case 6: op->base = UD_R_BP; break;
            case 7: op->base = UD_R_BX; break;
        }

        if (mod == 0 && rm == 6) {
            op->offset= 16;
            op->base = UD_NONE;
        }
        else if (mod == 1)
            op->offset = 8;
        else if (mod == 2) 
            op->offset = 16;
    }
  }  

  
  switch(op->offset) {
    case 8 : op->lval.ubyte  = inp_uint8(u);  break;
    case 16: op->lval.uword  = inp_uint16(u);  break;
    case 32: op->lval.udword = inp_uint32(u); break;
    default: break;
  }

  
  if (opreg) {
    opreg->type = UD_OP_REG;
    opreg->size = (uint8_t)resolve_operand_size(u, reg_size);
    if (reg_type == T_GPR) 
        opreg->base = decode_gpr(u, opreg->size, reg);
    else opreg->base = resolve_reg(u, reg_type, reg);
  }
}


static void 
decode_o(struct ud* u, unsigned int s, struct ud_operand *op)
{
  switch (u->adr_mode) {
    case 32:
        op->offset = 32; 
        op->lval.udword = inp_uint32(u); 
        break;
    case 16:
        op->offset = 16; 
        op->lval.uword  = inp_uint16(u); 
        break;
    default:
        return;
  }
  op->type = UD_OP_MEM;
  op->size = (uint8_t)resolve_operand_size(u, s);
}


static int disasm_operands(register struct ud* u)
{


  
  enum ud_operand_code mop1t = u->itab_entry->operand1.type;
  enum ud_operand_code mop2t = u->itab_entry->operand2.type;
  enum ud_operand_code mop3t = u->itab_entry->operand3.type;

  
  unsigned int mop1s = u->itab_entry->operand1.size;
  unsigned int mop2s = u->itab_entry->operand2.size;
  unsigned int mop3s = u->itab_entry->operand3.size;

  
  register struct ud_operand* iop = u->operand;
    
  switch(mop1t) {
    
    case OP_A :
        decode_a(u, &(iop[0]));
        break;
    
    
    case OP_M :
        if (MODRM_MOD(inp_peek(u)) == 3)
            u->error= 1;
    
    case OP_E :
        if (mop2t == OP_G) {
            decode_modrm(u, &(iop[0]), mop1s, T_GPR, &(iop[1]), mop2s, T_GPR);
            if (mop3t == OP_I)
                decode_imm(u, mop3s, &(iop[2]));
            else if (mop3t == OP_CL) {
                iop[2].type = UD_OP_REG;
                iop[2].base = UD_R_CL;
                iop[2].size = 8;
            }
        }
        else if (mop2t == OP_P)
            decode_modrm(u, &(iop[0]), mop1s, T_GPR, &(iop[1]), mop2s, T_MMX);
        else if (mop2t == OP_V)
            decode_modrm(u, &(iop[0]), mop1s, T_GPR, &(iop[1]), mop2s, T_XMM);
        else if (mop2t == OP_S)
            decode_modrm(u, &(iop[0]), mop1s, T_GPR, &(iop[1]), mop2s, T_SEG);
        else {
            decode_modrm(u, &(iop[0]), mop1s, T_GPR, NULL, 0, T_NONE);
            if (mop2t == OP_CL) {
                iop[1].type = UD_OP_REG;
                iop[1].base = UD_R_CL;
                iop[1].size = 8;
            } else if (mop2t == OP_I1) {
                iop[1].type = UD_OP_CONST;
                u->operand[1].lval.udword = 1;
            } else if (mop2t == OP_I) {
                decode_imm(u, mop2s, &(iop[1]));
            }
        }
        break;

    
    case OP_G :
        if (mop2t == OP_M) {
            if (MODRM_MOD(inp_peek(u)) == 3)
                u->error= 1;
            decode_modrm(u, &(iop[1]), mop2s, T_GPR, &(iop[0]), mop1s, T_GPR);
        } else if (mop2t == OP_E) {
            decode_modrm(u, &(iop[1]), mop2s, T_GPR, &(iop[0]), mop1s, T_GPR);
            if (mop3t == OP_I)
                decode_imm(u, mop3s, &(iop[2]));
        } else if (mop2t == OP_PR) {
            decode_modrm(u, &(iop[1]), mop2s, T_MMX, &(iop[0]), mop1s, T_GPR);
            if (mop3t == OP_I)
                decode_imm(u, mop3s, &(iop[2]));
        } else if (mop2t == OP_VR) {
            if (MODRM_MOD(inp_peek(u)) != 3)
                u->error = 1;
            decode_modrm(u, &(iop[1]), mop2s, T_XMM, &(iop[0]), mop1s, T_GPR);
        } else if (mop2t == OP_W)
            decode_modrm(u, &(iop[1]), mop2s, T_XMM, &(iop[0]), mop1s, T_GPR);
        break;

    
    case OP_AL : case OP_CL : case OP_DL : case OP_BL :
    case OP_AH : case OP_CH : case OP_DH : case OP_BH :

        iop[0].type = UD_OP_REG;
        iop[0].base = UD_R_AL + (mop1t - OP_AL);
        iop[0].size = 8;

        if (mop2t == OP_I)
            decode_imm(u, mop2s, &(iop[1]));
        else if (mop2t == OP_DX) {
            iop[1].type = UD_OP_REG;
            iop[1].base = UD_R_DX;
            iop[1].size = 16;
        }
        else if (mop2t == OP_O)
            decode_o(u, mop2s, &(iop[1]));
        break;

    
    case OP_rAXr8 : case OP_rCXr9 : case OP_rDXr10 : case OP_rBXr11 :
    case OP_rSPr12: case OP_rBPr13: case OP_rSIr14 : case OP_rDIr15 :
    case OP_rAX : case OP_rCX : case OP_rDX : case OP_rBX :
    case OP_rSP : case OP_rBP : case OP_rSI : case OP_rDI :

        iop[0].type = UD_OP_REG;
        iop[0].base = resolve_gpr64(u, mop1t);

        if (mop2t == OP_I)
            decode_imm(u, mop2s, &(iop[1]));
        else if (mop2t >= OP_rAX && mop2t <= OP_rDI) {
            iop[1].type = UD_OP_REG;
            iop[1].base = resolve_gpr64(u, mop2t);
        }
        else if (mop2t == OP_O) {
            decode_o(u, mop2s, &(iop[1]));  
            iop[0].size = (uint8_t)resolve_operand_size(u, mop2s);
        }
        break;

    
    case OP_ALr8b : case OP_CLr9b : case OP_DLr10b : case OP_BLr11b :
    case OP_AHr12b: case OP_CHr13b: case OP_DHr14b : case OP_BHr15b :
    {
        ud_type_t gpr = (mop1t - OP_ALr8b) + UD_R_AL + 
                        (REX_B(u->pfx_rex) << 3);
        if (UD_R_AH <= gpr && u->pfx_rex)
            gpr = gpr + 4;
        iop[0].type = UD_OP_REG;
        iop[0].base = gpr;
        if (mop2t == OP_I)
            decode_imm(u, mop2s, &(iop[1]));
        break;
    }

    
    case OP_eAX : case OP_eCX : case OP_eDX : case OP_eBX :
    case OP_eSP : case OP_eBP : case OP_eSI : case OP_eDI :
        iop[0].type = UD_OP_REG;
        iop[0].base = resolve_gpr32(u, mop1t);
        if (mop2t == OP_DX) {
            iop[1].type = UD_OP_REG;
            iop[1].base = UD_R_DX;
            iop[1].size = 16;
        } else if (mop2t == OP_I)
            decode_imm(u, mop2s, &(iop[1]));
        break;

    
    case OP_ES : case OP_CS : case OP_DS :
    case OP_SS : case OP_FS : case OP_GS :

        
        if (u->dis_mode == 64)
            if (mop1t != OP_FS && mop1t != OP_GS)
                u->error= 1;
        iop[0].type = UD_OP_REG;
        iop[0].base = (mop1t - OP_ES) + UD_R_ES;
        iop[0].size = 16;

        break;

    
    case OP_J :
        decode_imm(u, mop1s, &(iop[0]));        
        iop[0].type = UD_OP_JIMM;
        break ;

    
    case OP_PR:
        if (MODRM_MOD(inp_peek(u)) != 3)
            u->error = 1;
        decode_modrm(u, &(iop[0]), mop1s, T_MMX, NULL, 0, T_NONE);
        if (mop2t == OP_I)
            decode_imm(u, mop2s, &(iop[1]));
        break; 

    
    case OP_VR:
        if (MODRM_MOD(inp_peek(u)) != 3)
            u->error = 1;
        decode_modrm(u, &(iop[0]), mop1s, T_XMM, NULL, 0, T_NONE);
        if (mop2t == OP_I)
            decode_imm(u, mop2s, &(iop[1]));
        break; 

    
    case OP_P :
        if (mop2t == OP_Q) {
            decode_modrm(u, &(iop[1]), mop2s, T_MMX, &(iop[0]), mop1s, T_MMX);
            if (mop3t == OP_I)
                decode_imm(u, mop3s, &(iop[2]));
        } else if (mop2t == OP_W) {
            decode_modrm(u, &(iop[1]), mop2s, T_XMM, &(iop[0]), mop1s, T_MMX);
        } else if (mop2t == OP_VR) {
            if (MODRM_MOD(inp_peek(u)) != 3)
                u->error = 1;
            decode_modrm(u, &(iop[1]), mop2s, T_XMM, &(iop[0]), mop1s, T_MMX);
        } else if (mop2t == OP_E) {
            decode_modrm(u, &(iop[1]), mop2s, T_GPR, &(iop[0]), mop1s, T_MMX);
            if (mop3t == OP_I)
                decode_imm(u, mop3s, &(iop[2]));
        }
        break;

    
    case OP_R :
        if (mop2t == OP_C)
            decode_modrm(u, &(iop[0]), mop1s, T_GPR, &(iop[1]), mop2s, T_CRG);
        else if (mop2t == OP_D)
            decode_modrm(u, &(iop[0]), mop1s, T_GPR, &(iop[1]), mop2s, T_DBG);
        break;

    
    case OP_C :
        decode_modrm(u, &(iop[1]), mop2s, T_GPR, &(iop[0]), mop1s, T_CRG);
        break;

    
    case OP_D :
        decode_modrm(u, &(iop[1]), mop2s, T_GPR, &(iop[0]), mop1s, T_DBG);
        break;

    
    case OP_Q :
        decode_modrm(u, &(iop[0]), mop1s, T_MMX, &(iop[1]), mop2s, T_MMX);
        break;

    
    case OP_S :
        decode_modrm(u, &(iop[1]), mop2s, T_GPR, &(iop[0]), mop1s, T_SEG);
        break;

    
    case OP_W :
        decode_modrm(u, &(iop[0]), mop1s, T_XMM, &(iop[1]), mop2s, T_XMM);
        break;

    
    case OP_V :
        if (mop2t == OP_W) {
            
            if (MODRM_MOD(inp_peek(u)) == 3) {
                if (u->mnemonic == UD_Imovlps)
                    u->mnemonic = UD_Imovhlps;
                else
                if (u->mnemonic == UD_Imovhps)
                    u->mnemonic = UD_Imovlhps;
            }
            decode_modrm(u, &(iop[1]), mop2s, T_XMM, &(iop[0]), mop1s, T_XMM);
            if (mop3t == OP_I)
                decode_imm(u, mop3s, &(iop[2]));
        } else if (mop2t == OP_Q)
            decode_modrm(u, &(iop[1]), mop2s, T_MMX, &(iop[0]), mop1s, T_XMM);
        else if (mop2t == OP_M) {
            if (MODRM_MOD(inp_peek(u)) == 3)
                u->error= 1;
            decode_modrm(u, &(iop[1]), mop2s, T_GPR, &(iop[0]), mop1s, T_XMM);
        } else if (mop2t == OP_E) {
            decode_modrm(u, &(iop[1]), mop2s, T_GPR, &(iop[0]), mop1s, T_XMM);
        } else if (mop2t == OP_PR) {
            decode_modrm(u, &(iop[1]), mop2s, T_MMX, &(iop[0]), mop1s, T_XMM);
        }
        break;

    
    case OP_DX :
        iop[0].type = UD_OP_REG;
        iop[0].base = UD_R_DX;
        iop[0].size = 16;

        if (mop2t == OP_eAX) {
            iop[1].type = UD_OP_REG;    
            iop[1].base = resolve_gpr32(u, mop2t);
        } else if (mop2t == OP_AL) {
            iop[1].type = UD_OP_REG;
            iop[1].base = UD_R_AL;
            iop[1].size = 8;
        }

        break;

    
    case OP_I :
        decode_imm(u, mop1s, &(iop[0]));
        if (mop2t == OP_I)
            decode_imm(u, mop2s, &(iop[1]));
        else if (mop2t == OP_AL) {
            iop[1].type = UD_OP_REG;
            iop[1].base = UD_R_AL;
            iop[1].size = 16;
        } else if (mop2t == OP_eAX) {
            iop[1].type = UD_OP_REG;    
            iop[1].base = resolve_gpr32(u, mop2t);
        }
        break;

    
    case OP_O :
        decode_o(u, mop1s, &(iop[0]));
        iop[1].type = UD_OP_REG;
        iop[1].size = (uint8_t)resolve_operand_size(u, mop1s);
        if (mop2t == OP_AL)
            iop[1].base = UD_R_AL;
        else if (mop2t == OP_eAX)
            iop[1].base = resolve_gpr32(u, mop2t);
        else if (mop2t == OP_rAX)
            iop[1].base = resolve_gpr64(u, mop2t);      
        break;

    
    case OP_I3 :
        iop[0].type = UD_OP_CONST;
        iop[0].lval.sbyte = 3;
        break;

    
    case OP_ST0 : case OP_ST1 : case OP_ST2 : case OP_ST3 :
    case OP_ST4 : case OP_ST5 : case OP_ST6 : case OP_ST7 :

        iop[0].type = UD_OP_REG;
        iop[0].base = (mop1t-OP_ST0) + UD_R_ST0;
        iop[0].size = 0;

        if (mop2t >= OP_ST0 && mop2t <= OP_ST7) {
            iop[1].type = UD_OP_REG;
            iop[1].base = (mop2t-OP_ST0) + UD_R_ST0;
            iop[1].size = 0;
        }
        break;

    
    case OP_AX:
        iop[0].type = UD_OP_REG;
        iop[0].base = UD_R_AX;
        iop[0].size = 16;
        break;

    
    default :
        iop[0].type = iop[1].type = iop[2].type = UD_NONE;
  }

  return 0;
}


static int clear_insn(register struct ud* u)
{
  u->error     = 0;
  u->pfx_seg   = 0;
  u->pfx_opr   = 0;
  u->pfx_adr   = 0;
  u->pfx_lock  = 0;
  u->pfx_repne = 0;
  u->pfx_rep   = 0;
  u->pfx_repe  = 0;
  u->pfx_seg   = 0;
  u->pfx_rex   = 0;
  u->pfx_insn  = 0;
  u->mnemonic  = UD_Inone;
  u->itab_entry = NULL;

  vmm_memset( &u->operand[ 0 ], 0, sizeof( struct ud_operand ) );
  vmm_memset( &u->operand[ 1 ], 0, sizeof( struct ud_operand ) );
  vmm_memset( &u->operand[ 2 ], 0, sizeof( struct ud_operand ) );
 
  return 0;
}

static int do_mode( struct ud* u )
{
  
  if ( u->error ) return -1; 

  
  if ( u->dis_mode == 64 ) {  

    
    if ( P_INV64( u->itab_entry->prefix ) ) {
        u->error = 1;
        return -1;
    }

    
    u->pfx_rex = ( u->pfx_rex & 0x40 ) | 
                 ( u->pfx_rex & REX_PFX_MASK( u->itab_entry->prefix ) ); 

    
    u->default64 = P_DEF64( u->itab_entry->prefix ); 
    
    if ( REX_W( u->pfx_rex ) ) {
        u->opr_mode = 64;
    } else if ( u->pfx_opr ) {
        u->opr_mode = 16;
    } else {
        
        u->opr_mode = ( u->default64 ) ? 64 : 32;
    }

    
    u->adr_mode = (u->pfx_adr) ? 32 : 64;
  } else if ( u->dis_mode == 32 ) { 
    u->opr_mode = ( u->pfx_opr ) ? 16 : 32;
    u->adr_mode = ( u->pfx_adr ) ? 16 : 32;
  } else if ( u->dis_mode == 16 ) { 
    u->opr_mode = ( u->pfx_opr ) ? 32 : 16;
    u->adr_mode = ( u->pfx_adr ) ? 32 : 16;
  }

  
  u->c1 = ( P_C1( u->itab_entry->prefix ) ) ? 1 : 0;
  u->c2 = ( P_C2( u->itab_entry->prefix ) ) ? 1 : 0;
  u->c3 = ( P_C3( u->itab_entry->prefix ) ) ? 1 : 0;

  
  u->implicit_addr = P_IMPADDR( u->itab_entry->prefix );

  return 0;
}

static int gen_hex( struct ud *u )
{
  unsigned int i;
  unsigned char *src_ptr = inp_sess( u );
  char* src_hex;

  
  if ( u->error ) return -1;
  
  src_hex = ( char* ) u->insn_hexcode;
  
  for ( i = 0; i < u->inp_ctr; ++i, ++src_ptr) {
    vmm_snprintf( src_hex, 32, "%02x", *src_ptr & 0xFF );
    src_hex += 2;
  }
  return 0;
}


unsigned int ud_decode( struct ud* u )
{
  inp_start(u);

  if ( clear_insn( u ) ) {
    ; 
  } else if ( get_prefixes( u ) != 0 ) {
    ; 
  } else if ( search_itab( u ) != 0 ) {
    ; 
  } else if ( do_mode( u ) != 0 ) {
    ; 
  } else if ( disasm_operands( u ) != 0 ) {
    ; 
  } else if ( resolve_mnemonic( u ) != 0 ) {
    ; 
  }

  
  if ( u->error ) {
    
    clear_insn( u );
    
    u->itab_entry = & ie_invalid;
    u->mnemonic = u->itab_entry->mnemonic;
  } 

  u->insn_offset = u->pc; 
  u->insn_fill = 0;   
  u->pc += u->inp_ctr;    
  gen_hex( u );       

  
  return u->inp_ctr;
}


