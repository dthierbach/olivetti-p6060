/* example r_asm plugin by pancake at 2014 */

#include <r_asm.h>
#include <r_lib.h>

enum p6060_mask {
  MASK = 1,
  MASK_BC,
  MASK_BCR
};

enum p6060_instr_format {
  INVALID = 0,
  INSTR_RR_RR,
  INSTR_RR_0R,
  INSTR_RR_U0,
  INSTR_RR_UR,
  INSTR_RR_MR,
  INSTR_RX_RRRD,
  INSTR_RX_0RRD,
  INSTR_RX_MRRD,
  INSTR_RS_RRRD,
  INSTR_SI_URD,
  INSTR_SS_LLRDRD,
  INSTR_SS_L0RDRD,
  INSTR_SS_0RDRD,
  INSTR_SS_0LRDRD,
  INSTR_SS_NBD
};

struct p6060_opcode {
  char* name;
  ut8 opcode;
  enum p6060_mask mask;
  enum p6060_instr_format format;
  char *description;
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

struct p6060_opcode opcode_bc_list[] = {
   { "bo"    ,    1, MASK_BC    , INSTR_RX_0RRD  , "branch on overflow"  },
// { "bh"    ,    2, MASK_BC    , INSTR_RX_0RRD  , "branch on high"      },
   { "bp"    ,    2, MASK_BC    , INSTR_RX_0RRD  , "branch on plus"      },
// { "bl"    ,    4, MASK_BC    , INSTR_RX_0RRD  , "branch on low"       },
   { "bm"    ,    4, MASK_BC    , INSTR_RX_0RRD  , "branch on minus"     },
   { "bne"   ,    6, MASK_BC    , INSTR_RX_0RRD  , "branch on not equal" },
// { "bnz"   ,    6, MASK_BC    , INSTR_RX_0RRD  , "branch on not zero"  },
   { "be"    ,    8, MASK_BC    , INSTR_RX_0RRD  , "branch on equal"     },
// { "bz"    ,    8, MASK_BC    , INSTR_RX_0RRD  , "branch on zero"      },
// { "bnl"   ,   10, MASK_BC    , INSTR_RX_0RRD  , "branch on not low"   },
   { "bnm"   ,   10, MASK_BC    , INSTR_RX_0RRD  , "branch on not minus" },
// { "bnh"   ,   13, MASK_BC    , INSTR_RX_0RRD  , "branch on not high"  },
   { "bnp"   ,   13, MASK_BC    , INSTR_RX_0RRD  , "branch on not plus"  },
   { "bno"   ,   14, MASK_BC    , INSTR_RX_0RRD  , "branch on not ones"  },
   { "b"     ,   15, MASK_BC    , INSTR_RX_0RRD  , "branch"              },
   { "nop"   ,    0, MASK_BC    , INSTR_RX_0RRD  , "no operation"        },
   { NULL    ,    0, 0          , 0              ,  ""}
};

struct p6060_opcode opcode_bcr_list[] = {
   { "bor"   ,    1, MASK_BCR   , INSTR_RR_0R    , "branch on overflow"  },
// { "bhr"   ,    2, MASK_BCR   , INSTR_RR_0R    , "branch on high"      },
   { "bpr"   ,    2, MASK_BCR   , INSTR_RR_0R    , "branch on plus"      },
// { "blr"   ,    4, MASK_BCR   , INSTR_RR_0R    , "branch on low"       },
   { "bmr"   ,    4, MASK_BCR   , INSTR_RR_0R    , "branch on minus"     },
   { "bner"  ,    6, MASK_BCR   , INSTR_RR_0R    , "branch on not equal" },
// { "bnzr"  ,    6, MASK_BCR   , INSTR_RR_0R    , "branch on not zero"  },
   { "ber"   ,    8, MASK_BCR   , INSTR_RR_0R    , "branch on equal"     },
// { "bzr"   ,    8, MASK_BCR   , INSTR_RR_0R    , "branch on zero"      },
// { "bnlr"  ,   10, MASK_BCR   , INSTR_RR_0R    , "branch on not low"   },
   { "bnmr"  ,   10, MASK_BCR   , INSTR_RR_0R    , "branch on not minus" },
// { "bnhr"  ,   13, MASK_BCR   , INSTR_RR_0R    , "branch on not high"  },
   { "bnpr"  ,   13, MASK_BCR   , INSTR_RR_0R    , "branch on not plus"  },
   { "bnor"  ,   14, MASK_BCR   , INSTR_RR_0R    , "branch on not ones"  },
   { "br"    ,   15, MASK_BCR   , INSTR_RR_0R    , "branch"              },
   { "nopr"  ,    0, MASK_BCR   , INSTR_RR_0R    , "no operation"        },
   { NULL    ,    0, 0          , 0              ,  ""}
};

struct p6060_opcode opcode_list[] = {
  { "a"     , 0x5A, MASK       , INSTR_RX_RRRD   , "add"                                  },
  { "ah"    , 0x4A, MASK       , INSTR_RX_RRRD   , "add halfword"                         },
  { "al"    , 0x5E, MASK       , INSTR_RX_RRRD   , "add logical"                          },
  { "alm"   , 0xFB, MASK       , INSTR_SS_LLRDRD , "add logical memory"                   },
  { "alr"   , 0x1E, MASK       , INSTR_RR_RR     , "add logical register"                 },
  { "alri"  , 0x01, MASK       , INSTR_RR_UR     , "add logical register immediate"       },
  { "am"    , 0xFA, MASK       , INSTR_SS_LLRDRD , "add memory"                           },
  { "ar"    , 0x1A, MASK       , INSTR_RR_RR     , "add register"                         },
  { "bal"   , 0x45, MASK       , INSTR_RX_RRRD   , "branch and link"                      },
  { "balr"  , 0x05, MASK       , INSTR_RR_RR     , "branch and link register"             },
  { "bc"    , 0x47, MASK_BC    , INSTR_RX_MRRD   , "branch on condition"                  },
  { "bcr"   , 0x07, MASK_BCR   , INSTR_RR_MR     , "branch on condition register"         },
  { "bct"   , 0x46, MASK       , INSTR_RX_RRRD   , "branch on count"                      },
  { "bctr"  , 0x06, MASK       , INSTR_RR_RR     , "branch on count register"             },
  { "bxh"   , 0x86, MASK       , INSTR_RS_RRRD   , "branch on index high"                 },
  { "bxle"  , 0x87, MASK       , INSTR_RS_RRRD   , "branch on index low or equal"         },
  { "c"     , 0x59, MASK       , INSTR_RX_RRRD   , "compare"                              },
  { "ch"    , 0x49, MASK       , INSTR_RX_RRRD   , "compare halfword"                     },
  { "cl"    , 0x55, MASK       , INSTR_RX_RRRD   , "compare logical"                      },
  { "clc"   , 0xD5, MASK       , INSTR_SS_L0RDRD , "compare logical character"            },
  { "cli"   , 0x95, MASK       , INSTR_SI_URD    , "compare logical immediate"            },
  { "clm"   , 0xF5, MASK       , INSTR_SS_LLRDRD , "compare logical memory"               },
  { "clr"   , 0x15, MASK       , INSTR_RR_RR     , "compare logical register"             },
  { "cm"    , 0xF9, MASK       , INSTR_SS_LLRDRD , "compare memory"                       },
  { "cr"    , 0x19, MASK       , INSTR_RR_RR     , "compare register"                     },
  { "dm"    , 0x85, MASK       , INSTR_RS_RRRD   , "divide memory"                        },
  { "ex"    , 0x44, MASK       , INSTR_RX_RRRD   , "execute"                              },
  { "ic"    , 0x43, MASK       , INSTR_RX_RRRD   , "insert character"                     },
  { "im"    , 0x9D, MASK       , INSTR_SI_URD    , "immediate in memory"                  },
  { "iso"   , 0x82, MASK       , INSTR_RX_0RRD   , "iso (ascii) test"                     },
  { "l"     , 0x58, MASK       , INSTR_RX_RRRD   , "load"                                 },
  { "la"    , 0x41, MASK       , INSTR_RX_RRRD   , "load address"                         },
  { "lc"    , 0x53, MASK       , INSTR_RX_RRRD   , "load complement"                      },
  { "lcr"   , 0x13, MASK       , INSTR_RR_RR     , "load complement register"             },
  { "lh"    , 0x48, MASK       , INSTR_RX_RRRD   , "load halfword"                        },
  { "lm"    , 0x98, MASK       , INSTR_RS_RRRD   , "load multiple"                        },
  { "ln"    , 0x51, MASK       , INSTR_RX_RRRD   , "load negative"                        },
  { "lnr"   , 0x11, MASK       , INSTR_RR_RR     , "load negative register"               },
  { "lpr"   , 0x10, MASK       , INSTR_RR_RR     , "load positive register (absolute)"    },
  { "lr"    , 0x18, MASK       , INSTR_RR_RR     , "load register"                        },
  { "lt"    , 0x52, MASK       , INSTR_RX_RRRD   , "load and test"                        },
  { "ltr"   , 0x12, MASK       , INSTR_RR_RR     , "load and test register"               },
  { "mlh"   , 0x83, MASK       , INSTR_RX_RRRD   , "multiply logical halfword"            },
  { "mlr"   , 0x26, MASK       , INSTR_RR_RR     , "multiply logical register"            },
  { "mvc"   , 0xD2, MASK       , INSTR_SS_L0RDRD , "move character(s)"                    },
  { "mvcr"  , 0xF2, MASK       , INSTR_SS_0RDRD  , "move character(s) register"           },
  { "mvi"   , 0x92, MASK       , INSTR_SI_URD    , "move immediate"                       },
  { "mvn"   , 0xD1, MASK       , INSTR_SS_L0RDRD , "move nibbles"                         },
  { "mvo"   , 0xF1, MASK       , INSTR_SS_LLRDRD , "move with offset"                     },
  { "mvz"   , 0xD3, MASK       , INSTR_SS_L0RDRD , "move zones"                           },
  { "n"     , 0x54, MASK       , INSTR_RX_RRRD   , "and"                                  },
  { "nc"    , 0xD4, MASK       , INSTR_SS_L0RDRD , "and character"                        },
  { "ni"    , 0x94, MASK       , INSTR_SI_URD    , "and immediate"                        },
  { "nr"    , 0x14, MASK       , INSTR_RR_RR     , "and register"                         },
  { "o"     , 0x56, MASK       , INSTR_RX_RRRD   , "or"                                   },
  { "oc"    , 0xD6, MASK       , INSTR_SS_LLRDRD , "or character"                         },
  { "oi"    , 0x96, MASK       , INSTR_SI_URD    , "or immediate"                         },
  { "or"    , 0x16, MASK       , INSTR_RR_RR     , "or register"                          },
  { "s"     , 0x5B, MASK       , INSTR_RX_RRRD   , "substract"                            },
  { "sh"    , 0x4B, MASK       , INSTR_RX_RRRD   , "subtract halfword"                    },
  { "sl"    , 0x5F, MASK       , INSTR_RX_RRRD   , "subtract logical"                     },
  { "sla"   , 0x02, MASK       , INSTR_RR_UR     , "shift left algebraic"                 },
  { "sll"   , 0x04, MASK       , INSTR_RR_UR     , "shift left logical"                   },
  { "slm"   , 0xF4, MASK       , INSTR_SS_LLRDRD , "subtract logical memory"              },
  { "slr"   , 0x1F, MASK       , INSTR_RR_RR     , "subtract logical register"            },
  { "slri"  , 0x0C, MASK       , INSTR_RR_UR     , "subtract logical register immediate"  },
  { "sm"    , 0xF3, MASK       , INSTR_SS_LLRDRD , "subtract memory"                      },
  { "sr"    , 0x1B, MASK       , INSTR_RR_RR     , "subtract register"                    },
  { "sra"   , 0x03, MASK       , INSTR_RR_UR     , "shift right algebraic"                },
  { "srl"   , 0x08, MASK       , INSTR_RR_UR     , "shift right logical"                  },
  { "st"    , 0x50, MASK       , INSTR_RX_RRRD   , "store"                                },
  { "stc"   , 0x42, MASK       , INSTR_RX_RRRD   , "store charcter"                       },
  { "sth"   , 0x40, MASK       , INSTR_RX_RRRD   , "store halfword"                       },
  { "stm"   , 0x90, MASK       , INSTR_RS_RRRD   , "store multiple"                       },
  { "tm"    , 0x91, MASK       , INSTR_SI_URD    , "test under mask"                      },
  { "tr"    , 0xDC, MASK       , INSTR_SS_L0RDRD , "translate"                            },
  { "trt"   , 0xD0, MASK       , INSTR_SS_L0RDRD , "translate and test"                   },
  { "x"     , 0x57, MASK       , INSTR_RX_RRRD   , "exclusive or"                         },
  { "xc"    , 0xD7, MASK       , INSTR_SS_LLRDRD , "exclusive or character"               },
  { "xi"    , 0x97, MASK       , INSTR_SI_URD    , "exclusive or immediate"               },
  { "xr"    , 0x17, MASK       , INSTR_RR_RR     , "exclusive or register"                },
  { "asa"   , 0x23, MASK       , INSTR_RR_RR     , "allocate stack area"                  },
  { "fsa"   , 0x22, MASK       , INSTR_RR_RR     , "free stack area"                      },
  { "cbs"   , 0xDB, MASK       , INSTR_SS_L0RDRD , "binary to iso (ascii) conversion"     },
  { "csbh"  , 0xF6, MASK       , INSTR_SS_0LRDRD , "iso (ascii) to binary conversion"     },
  { "dis"   , 0xF8, MASK       , INSTR_SS_LLRDRD , "dicotomic search"                     },
  { "lie"   , 0x99, MASK       , INSTR_SI_URD    , "look for immediate equal"             },
  { "line"  , 0x9B, MASK       , INSTR_SI_URD    , "look for immediate not equal"         },
  { "ses"   , 0xF7, MASK       , INSTR_SS_LLRDRD , "sequential search"                    },
  { "sesm"  , 0xF0, MASK       , INSTR_SS_LLRDRD , "sequential search with mask"          },
  { "call"  , 0x9A, MASK       , INSTR_SS_NBD    , "subroutine call"                      },
  { "rets"  , 0x20, MASK       , INSTR_RR_U0     , "subroutine return"                    },
  // ??            ACT       active module
  { "calexs", 0x9c, MASK       , INSTR_SS_NBD    , "call external system module"          },
  // ??            CALEXT    call external
  { "retext", 0x28, MASK       , INSTR_RR_U0     , "return from external module"          }, // RR_U0 is guess
  // ??            RLSEM     release module
  { "svc"   , 0x0a, MASK       , INSTR_RR_U0     , "supervisor call"                      },
  { "??0b"  , 0x0b, MASK       , INSTR_RR_RR     , "unknown"                              },
  { "??93"  , 0x93, MASK       , INSTR_RS_RRRD   , "unknown"                              }, // RS is guess
  { "??4e"  , 0x4e, MASK       , INSTR_RS_RRRD   , "unknown"                              }, // RS is guess
  { "??4f"  , 0x4f, MASK       , INSTR_RS_RRRD   , "unknown"                              }, // RS is guess
  { NULL    , 0   , 0          , 0              ,  ""}
};

static struct p6060_opcode* opcode[256];
static struct p6060_opcode* opcode_bc[16];
static struct p6060_opcode* opcode_bcr[16];

static bool p6060_init(void *user) {
  for (int i = 0; i < 256; i++) {
    opcode[i] = NULL;
  }
  for (int i = 0; i < 16; i++) {
    opcode_bc[i] = NULL;
    opcode_bcr[i] = NULL;
  }
  struct p6060_opcode** op;
  for (int i = 0; opcode_list[i].name != NULL; i++) {
    opcode[opcode_list[i].opcode] = &opcode_list[i];
  }
  for (int i = 0; opcode_bc_list[i].name != NULL; i++) {
    opcode_bc[opcode_bc_list[i].opcode] = &opcode_bc_list[i];
  }
  for (int i = 0; opcode_bcr_list[i].name != NULL; i++) {
    opcode_bcr[opcode_bcr_list[i].opcode] = &opcode_bcr_list[i];
  }
  return true; // true = successful init??
}

// most and least significant nibble
#define MSN(b,n) ((b[n])>>4)
#define LSN(b,n) ((b[n])&0xf)

static void disp_rrd(RStrBuf *sb, const ut8 rx, const ut8 *b, int n)
{
  ut8 rb = MSN(b, n);
  r_strbuf_appendf (sb, "%d", (LSN(b,n) << 8) | b[n+1]);
  if (rx != 0 || rb != 0) {
    r_strbuf_append (sb, "(");
    if (rx != 0) {
      r_strbuf_appendf (sb, "r%d", rx);
    }
    if (rb != 0) {
      r_strbuf_appendf (sb, ",r%d", rb);
    }
    r_strbuf_append (sb, ")");
  }
};

static void disp_lrd(RStrBuf *sb, const ut8 rl, const ut8 *b, int n)
{
  ut8 rb = MSN(b, n);
  r_strbuf_appendf (sb, "%d", (LSN(b,n) << 8) | b[n+1]);
  if (rl != 0 || rb != 0) {
    r_strbuf_append (sb, "(");
    if (rl != 0) {
      r_strbuf_appendf (sb, "%d", rl);
    }
    if (rb != 0) {
      r_strbuf_appendf (sb, ",r%d", rb);
    }
    r_strbuf_append (sb, ")");
  }
};

static void disp_rd(RStrBuf *sb, const ut8 *b, int n)
{
  ut8 rb = MSN(b, n);
  r_strbuf_appendf (sb, "%d", (LSN(b,n) << 8) | b[n+1]);
  if (rb != 0) {
    r_strbuf_appendf (sb, "(r%d)", rb);
  }
};

static int p6060_disassemble (RAsm *a, RAsmOp *op, const ut8 *b, int l)
{
  int n;
  struct p6060_opcode* opc = opcode[b[0]];
  op->size = 1;
  if (!opc) {
    r_strbuf_set (&op->buf_asm, "invalid");
    return -1;
  }
  if (opc->mask == MASK_BC) {
    n = MSN(b,1);
    if (opcode_bc[n]) {
      opc = opcode_bc[n];
    }
  }
  if (opc->mask == MASK_BCR) {
    n = MSN(b,1);
    if (opcode_bcr[n]) {
      opc = opcode_bcr[n];
    }
  }
  r_strbuf_set (&op->buf_asm, opc->name);
  r_strbuf_append (&op->buf_asm, " ");
  switch(opc->format) {
    case INSTR_RR_RR:
      r_strbuf_appendf (&op->buf_asm, "r%d, r%d", MSN(b,1), LSN(b,1));
      op->size = 2;
      break;
    case INSTR_RR_0R:
      r_strbuf_appendf (&op->buf_asm, "r%d", LSN(b,1));
      op->size = 2;
      break;
    case INSTR_RR_U0:
      r_strbuf_appendf (&op->buf_asm, "%d", b[1]);
      op->size = 2;
      break;
    case INSTR_RR_UR:
      r_strbuf_appendf (&op->buf_asm, "r%d, %d", LSN(b,1), MSN(b,1));
      op->size = 2;
      break;
    case INSTR_RR_MR:
      r_strbuf_appendf (&op->buf_asm, "%d, r%d", MSN(b,1), LSN(b,1));
      op->size = 2;
      break;
    case INSTR_RX_RRRD:
      r_strbuf_appendf (&op->buf_asm, "r%d, ", MSN(b,1));
      disp_rrd(&op->buf_asm, LSN(b,1), b, 2);
      op->size = 4;
      break;
    case INSTR_RX_0RRD:
      disp_rrd(&op->buf_asm, LSN(b,1), b, 2);
      op->size = 4;
      break;
    case INSTR_RX_MRRD:
      r_strbuf_appendf (&op->buf_asm, "%d, ", MSN(b,1));
      disp_rrd(&op->buf_asm, LSN(b,1), b, 2);
      op->size = 4;
      break;
    case INSTR_RS_RRRD:
      r_strbuf_appendf (&op->buf_asm, "r%d, r%d, ", MSN(b,1), LSN(b,1));
      disp_rd(&op->buf_asm, b, 2);
      op->size = 4;
      break;
    case INSTR_SI_URD:
      disp_rd(&op->buf_asm, b, 2);
      r_strbuf_appendf (&op->buf_asm, ", %d", b[1]);
      op->size = 4;
      break;
    case INSTR_SS_LLRDRD:
      disp_lrd(&op->buf_asm, MSN(b,1), b, 2);
      r_strbuf_append (&op->buf_asm, ", ");
      disp_lrd(&op->buf_asm, LSN(b,1), b, 4);
      op->size = 6;
      break;
    case INSTR_SS_L0RDRD:
      disp_lrd(&op->buf_asm, b[1], b, 2);
      r_strbuf_append (&op->buf_asm, ", ");
      disp_rd(&op->buf_asm, b, 4);
      op->size = 6;
      break;
    case INSTR_SS_0RDRD:
      disp_rd(&op->buf_asm, b, 2);
      r_strbuf_append (&op->buf_asm, ", ");
      disp_rd(&op->buf_asm, b, 4);
      op->size = 6;
      break;
    case INSTR_SS_0LRDRD:
      disp_rd(&op->buf_asm, b, 2);
      r_strbuf_append (&op->buf_asm, ", ");
      disp_lrd(&op->buf_asm, LSN(b,1), b, 4);
      op->size = 6;
      break;
    case INSTR_SS_NBD:
      n = b[1] & 0x1f;
      op->size = 4 + 2*n;
      disp_rd(&op->buf_asm, b, 2);
      for (int i = 1; i <= n; i++) {
	r_strbuf_append (&op->buf_asm, ", ");
	disp_rd(&op->buf_asm, b, 2+2*i);
      }
      break;
    case INVALID:
      break;
  }
  return op->size;
}

RAsmPlugin r_asm_plugin_p6060 = {
	.name = "p6060",
	.desc = "Olivetti P6060 disassembler",
	.arch = "p6060",
	.license = "LGPL3",
	.bits = 32,
	.endian = R_SYS_ENDIAN_BIG,
	.init = &p6060_init,
	.disassemble = &p6060_disassemble,
	.modify = NULL,
	.assemble = NULL,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
        .type = R_LIB_TYPE_ASM,
        .data = &r_asm_plugin_p6060,
	.version = R2_VERSION
};
#endif
