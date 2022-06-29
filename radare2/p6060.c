/* example r_asm plugin by pancake at 2014 */

#include <r_asm.h>
#include <r_lib.h>

enum p6060_instr_format {
  INSTR_RR = 1,
  INSTR_RX,
  INSTR_RS,
  INSTR_SI,
  INSTR_SS
};

struct p6060_opcode {
  char* name;
  ut8 opcode;
  enum p6060_instr_format format;
};

/*

BO      =BC  1  branch on overflow (ones?)
BH      =BC  2  branch on high
BP      =BC  2  branch on plus
BL      =BC  4  branch on low
BM      =BC  4  branch on minus
BNE     =BC  6  branch on not equal
BNZ     =BC  6  branch on not zero
BE      =BC  8  branch on equal
BZ      =BC  8  branch on zero
BNL     =BC 10  branch on not low
BNM     =BC 10  branch on not minus
BNH     =BC 13  branch on not high
BNP     =BC 13  branch on not plus
BNO     =BC 14  branch on not ones (overflow?)
B       =BC 15  branch
BR      =BCR 15 branch
NOP     =BC 0   no operation
NOPR    =BCR 0  no operation

*/

struct p6060_opcode opcode_list[] = {
  { "a"     , 0x5A, INSTR_RX },   // add
  { "ah"    , 0x4A, INSTR_RX },   // add halfword
  { "al"    , 0x5E, INSTR_RX },   // add logical
  { "alm"   , 0xFB, INSTR_SS },   // add logical memory
  { "alr"   , 0x1E, INSTR_RR },   // add logical register
  { "alri"  , 0x01, INSTR_RR },   // add logical register immediate
  { "am"    , 0xFA, INSTR_SS },   // add memory
  { "ar"    , 0x1A, INSTR_RR },   // add register
  { "bal"   , 0x45, INSTR_RX },   // branch and link
  { "balr"  , 0x05, INSTR_RR },   // branch and link register
  { "bc"    , 0x47, INSTR_RX },   // branch on condition (M1=C.C., 0 = NOP)
  { "bcr"   , 0x07, INSTR_RR },   // branch on condition register
  { "bct"   , 0x46, INSTR_RX },   // branch on count (decrement and branch)
  { "bctr"  , 0x06, INSTR_RR },   // branch on count register
  { "bxh"   , 0x86, INSTR_RS },   // branch on index high (range check?)
  { "bxle"  , 0x87, INSTR_RS },   // branch on index low or equal
  { "c"     , 0x59, INSTR_RX },   // compare
  { "ch"    , 0x49, INSTR_RX },   // compare halfword
  { "cl"    , 0x55, INSTR_RX },   // compare logical
  { "clc"   , 0xD5, INSTR_SS },   // compare logical character
  { "cli"   , 0x95, INSTR_SI },   // compare logical immediate
  { "clm"   , 0xF5, INSTR_SS },   // compare logical memory
  { "clr"   , 0x15, INSTR_RR },   // compare logical register
  { "cm"    , 0xF9, INSTR_SS },   // compare memory
  { "cr"    , 0x19, INSTR_RR },   // compare register
  { "dm"    , 0x85, INSTR_RS },   // divide memory
  { "ex"    , 0x44, INSTR_RX },   // execute
  { "ic"    , 0x43, INSTR_RX },   // insert character
  { "im"    , 0x9D, INSTR_SI },   // immediate in memory
  { "iso"   , 0x82, INSTR_RX },   // iso test (set CC: alpha=0, digit=1, operator=2, other=3)
  { "l"     , 0x58, INSTR_RX },   // load
  { "la"    , 0x41, INSTR_RX },   // load address (24 bit?)
  { "lc"    , 0x53, INSTR_RX },   // load complement
  { "lcr"   , 0x13, INSTR_RR },   // load complement register
  { "lh"    , 0x48, INSTR_RX },   // load halfword
  { "lm"    , 0x98, INSTR_RS },   // load multiple (regs R1-R2)
  { "ln"    , 0x51, INSTR_RX },   // load negative
  { "lnr"   , 0x11, INSTR_RR },   // load negative register
  { "lpr"   , 0x10, INSTR_RR },   // load positive register (absolute value)
  { "lr"    , 0x18, INSTR_RR },   // load register
  { "lt"    , 0x52, INSTR_RX },   // load and test (CC: =, <, >)
  { "ltr"   , 0x12, INSTR_RR },   // load and test register (CC: =, <, >)
  { "mlh"   , 0x83, INSTR_RX },   // multiply logical halfword
  { "mlr"   , 0x26, INSTR_RR },   // multiply logical register
  { "mvc"   , 0xD2, INSTR_SS },   // move character(s) (one length)
  { "mvcr"  , 0xF2, INSTR_SS },   // move character(s) on register (R0 = length)
  { "mvi"   , 0x92, INSTR_SI },   // move immediate
  { "mvn"   , 0xD1, INSTR_SS },   // move numerics (semibytes???)
  { "mvo"   , 0xF1, INSTR_SS },   // move with offset (two lengths, truncate/zero)
  { "mvz"   , 0xD3, INSTR_SS },   // move zones
  { "n"     , 0x54, INSTR_RX },   // and
  { "nc"    , 0xD4, INSTR_SS },   // and character
  { "ni"    , 0x94, INSTR_SI },   // and immediate
  { "nr"    , 0x14, INSTR_RR },   // and register
  { "o"     , 0x56, INSTR_RX },   // or
  { "oc"    , 0xD6, INSTR_SS },   // or character
  { "oi"    , 0x96, INSTR_SI },   // or immediate
  { "or"    , 0x16, INSTR_RR },   // or register
  { "s"     , 0x5B, INSTR_RX },   // substract
  { "sh"    , 0x4B, INSTR_RX },   // subtract halfword
  { "sl"    , 0x5F, INSTR_RX },   // subtract logical
  { "sla"   , 0x02, INSTR_RR },   // shift left algebraic
  { "sll"   , 0x04, INSTR_RR },   // shift left logical
  { "slm"   , 0xF4, INSTR_SS },   // subtract logical memory
  { "slr"   , 0x1F, INSTR_RR },   // subtract logical register
  { "slri"  , 0x0C, INSTR_RR },   // subtract logical register immediate
  { "sm"    , 0xF3, INSTR_SS },   // subtract memory
  { "sr"    , 0x1B, INSTR_RR },   // subtract register
  { "sra"   , 0x03, INSTR_RR },   // shift right algebraic
  { "srl"   , 0x08, INSTR_RR },   // shift right logical
  { "st"    , 0x50, INSTR_RX },   // store
  { "stc"   , 0x42, INSTR_RX },   // store charcter
  { "sth"   , 0x40, INSTR_RX },   // store halfword
  { "stm"   , 0x90, INSTR_RS },   // store multiple
  { "tm"    , 0x91, INSTR_SI },   // test under mask (CC:)
  { "tr"    , 0xDC, INSTR_SS },   // translate
  { "trt"   , 0xD0, INSTR_SS },   // translate and test
  { "x"     , 0x57, INSTR_RX },   // exclusive or
  { "xc"    , 0xD7, INSTR_SS },   // exclusive or character
  { "xi"    , 0x97, INSTR_SI },   // exclusive or immediate
  { "xr"    , 0x17, INSTR_RR },   // exclusive or register
  { "asa"   , 0x23, INSTR_RR },   // allocate stack area (R2=length, R1=?)
  { "fsa"   , 0x22, INSTR_RR },   // free stack area
  { "cbs"   , 0xDB, INSTR_SS },   // binary to iso (ascii) conversion
  { "csbh"  , 0xF6, INSTR_SS },   // iso (ascii) to binary conversion
  { "dis"   , 0xF8, INSTR_SS },   // dicotomic search
  { "lie"   , 0x99, INSTR_SI },   // look for immediate equal
  { "line"  , 0x9B, INSTR_SI },   // look for immediate not equal
  { "ses"   , 0xF7, INSTR_SS },   // sequential search
  { "sesm"  , 0xF0, INSTR_SS },   // sequential search with mask
  { "call"  , 0x9A, INSTR_SI },   // subroutine call
  { "rets"  , 0x20, INSTR_RR },   // subroutine return
  { NULL    , 0, 0}
};

static struct p6060_opcode* opcode[256];

static bool p6060_init(void *user) {
  for (int i = 0; i < 256; i++) {
    opcode[i] = NULL;
  }
  struct p6060_opcode** op;
  for (int i = 0; opcode_list[i].name != NULL; i++) {
    opcode[opcode_list[i].opcode] = &opcode_list[i];
  }
  return true; // true = successful init??
}

static int p6060_disassemble (RAsm *a, RAsmOp *op, const ut8 *b, int l) {
  char arg[32];
  struct p6060_opcode* opc = opcode[b[0]];
  op->size = 1;
  if (!opc) {
    r_strbuf_set (&op->buf_asm, "invalid");
    return -1;
  }
  r_strbuf_set (&op->buf_asm, opc->name);
  arg[0] = 0;
  switch(opc->format) {
    case INSTR_RR:
      op->size = 2;
      sprintf (arg, "r%d, r%d", b[1]>>4, b[1]&0xf);
      break;
    case INSTR_RX:
      op->size = 4;
      sprintf (arg, "r%d, 0x%x(r%d,r%d)", b[1]>>4, ((b[2]&0xf) << 8) | b[3], b[1]&0xf, b[2]>>4);
      break;
    case INSTR_RS:
      op->size = 4;
      sprintf (arg, "r%d, r%d, 0x%x(r%d)", b[1]>>4, b[1]&0xf, ((b[2]&0xf) << 8) | b[3], b[2]>>4);
      break;
    case INSTR_SI:
      op->size = 4;
      sprintf (arg, "0x%x, 0x%x(r%d)", b[1], ((b[2]&0xf) << 8) | b[3], b[2]>>4);
      break;
    case INSTR_SS:
      op->size = 6;
      sprintf (arg, "0x%x(r%d,r%d), 0x%x(r%d,r%d)", 
	       ((b[2]&0xf) << 8) | b[3], b[1]>>4,  b[2]>>4, 
	       ((b[4]&0xf) << 8) | b[5], b[1]&0xf, b[4]>>4);
      break;
  }
  if (*arg) {
    r_strbuf_append (&op->buf_asm, " ");
    r_strbuf_append (&op->buf_asm, arg);
  }
  return op->size;
}

RAsmPlugin r_asm_plugin_p6060 = {
        .name = "p6060",
        .arch = "p6060",
        .license = "LGPL3",
        .bits = 32,
	.endian = R_SYS_ENDIAN_BIG,
        .desc = "Olivetti P6060 disassembler",
	.init = &p6060_init,
        .disassemble = &p6060_disassemble,
	.modify = NULL,
	.assemble = NULL,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
        .type = R_LIB_TYPE_ASM,
        .data = &r_asm_plugin_p6060
};
#endif
