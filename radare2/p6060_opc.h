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
  _RAnalOpType type;	/* type of opcode */
  _RAnalCond cond;	/* condition type */
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
   { "bo"    ,    1, MASK_BC    , INSTR_RX_0RRD  , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_VS, "branch on overflow"  },
// { "bh"    ,    2, MASK_BC    , INSTR_RX_0RRD  , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_GT, "branch on high"      },
   { "bp"    ,    2, MASK_BC    , INSTR_RX_0RRD  , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_GT, "branch on plus"      },
// { "bl"    ,    4, MASK_BC    , INSTR_RX_0RRD  , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_LT, "branch on low"       },
   { "bm"    ,    4, MASK_BC    , INSTR_RX_0RRD  , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_LT, "branch on minus"     },
   { "bne"   ,    6, MASK_BC    , INSTR_RX_0RRD  , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_NE, "branch on not equal" },
// { "bnz"   ,    6, MASK_BC    , INSTR_RX_0RRD  , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_NE, "branch on not zero"  },
   { "be"    ,    8, MASK_BC    , INSTR_RX_0RRD  , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_EQ, "branch on equal"     },
// { "bz"    ,    8, MASK_BC    , INSTR_RX_0RRD  , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_EQ, "branch on zero"      },
// { "bnl"   ,   10, MASK_BC    , INSTR_RX_0RRD  , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_VS, "branch on not low"   },
   { "bnm"   ,   10, MASK_BC    , INSTR_RX_0RRD  , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_GE, "branch on not minus" },
// { "bnh"   ,   13, MASK_BC    , INSTR_RX_0RRD  , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_LE, "branch on not high"  },
   { "bnp"   ,   13, MASK_BC    , INSTR_RX_0RRD  , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_LE, "branch on not plus"  },
   { "bno"   ,   14, MASK_BC    , INSTR_RX_0RRD  , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_VC, "branch on not ones"  },
   { "b"     ,   15, MASK_BC    , INSTR_RX_0RRD  , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_AL, "branch"              },
   { "nop"   ,    0, MASK_BC    , INSTR_RX_0RRD  , R_ANAL_OP_TYPE_NOP,  0,              "no operation"        },
   { NULL    ,    0, 0          , 0              , 0, 0,                                ""}
};

struct p6060_opcode opcode_bcr_list[] = {
   { "bor"   ,    1, MASK_BCR   , INSTR_RR_0R    , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_VS, "branch on overflow"  },
// { "bhr"   ,    2, MASK_BCR   , INSTR_RR_0R    , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_GT, "branch on high"      },
   { "bpr"   ,    2, MASK_BCR   , INSTR_RR_0R    , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_GT, "branch on plus"      },
// { "blr"   ,    4, MASK_BCR   , INSTR_RR_0R    , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_LT, "branch on low"       },
   { "bmr"   ,    4, MASK_BCR   , INSTR_RR_0R    , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_LT, "branch on minus"     },
   { "bner"  ,    6, MASK_BCR   , INSTR_RR_0R    , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_NE, "branch on not equal" },
// { "bnzr"  ,    6, MASK_BCR   , INSTR_RR_0R    , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_NE, "branch on not zero"  },
   { "ber"   ,    8, MASK_BCR   , INSTR_RR_0R    , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_EQ, "branch on equal"     },
// { "bzr"   ,    8, MASK_BCR   , INSTR_RR_0R    , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_EQ, "branch on zero"      },
// { "bnlr"  ,   10, MASK_BCR   , INSTR_RR_0R    , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_VS, "branch on not low"   },
   { "bnmr"  ,   10, MASK_BCR   , INSTR_RR_0R    , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_GE, "branch on not minus" },
// { "bnhr"  ,   13, MASK_BCR   , INSTR_RR_0R    , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_LE, "branch on not high"  },
   { "bnpr"  ,   13, MASK_BCR   , INSTR_RR_0R    , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_LE, "branch on not plus"  },
   { "bnor"  ,   14, MASK_BCR   , INSTR_RR_0R    , R_ANAL_OP_TYPE_CJMP, R_ANAL_COND_VC, "branch on not ones"  },
   { "br"    ,   15, MASK_BCR   , INSTR_RR_0R    , R_ANAL_OP_TYPE_JMP,  R_ANAL_COND_AL, "branch"              },
   { "nopr"  ,    0, MASK_BCR   , INSTR_RR_0R    , R_ANAL_OP_TYPE_NOP,  0,              "no operation"        },
   { NULL    ,    0, 0          , 0              , 0, 0,                                ""}
};

struct p6060_opcode opcode_list[] = {
  { "a"     , 0x5A, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_ADD   , 0, "add"                                  },
  { "ah"    , 0x4A, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_ADD   , 0, "add halfword"                         },
  { "al"    , 0x5E, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_ADD   , 0, "add logical"                          },
  { "alm"   , 0xFB, MASK       , INSTR_SS_LLRDRD , R_ANAL_OP_TYPE_ADD   , 0, "add logical memory"                   },
  { "alr"   , 0x1E, MASK       , INSTR_RR_RR     , R_ANAL_OP_TYPE_ADD   , 0, "add logical register"                 },
  { "alri"  , 0x01, MASK       , INSTR_RR_UR     , R_ANAL_OP_TYPE_ADD   , 0, "add logical register immediate"       },
  { "am"    , 0xFA, MASK       , INSTR_SS_LLRDRD , R_ANAL_OP_TYPE_ADD   , 0, "add memory"                           },
  { "ar"    , 0x1A, MASK       , INSTR_RR_RR     , R_ANAL_OP_TYPE_ADD   , 0, "add register"                         },
  { "bal"   , 0x45, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_CALL  , 0, "branch and link"                      },
  { "balr"  , 0x05, MASK       , INSTR_RR_RR     , R_ANAL_OP_TYPE_UCALL , 0, "branch and link register"             },
  { "bc"    , 0x47, MASK_BC    , INSTR_RX_MRRD   , R_ANAL_OP_TYPE_CJMP  , 0, "branch on condition"                  },
  { "bcr"   , 0x07, MASK_BCR   , INSTR_RR_MR     , R_ANAL_OP_TYPE_CJMP  , 0, "branch on condition register"         },
  { "bct"   , 0x46, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_NULL  , 0, "branch on count"                      },
  { "bctr"  , 0x06, MASK       , INSTR_RR_RR     , R_ANAL_OP_TYPE_NULL  , 0, "branch on count register"             },
  { "bxh"   , 0x86, MASK       , INSTR_RS_RRRD   , R_ANAL_OP_TYPE_NULL  , 0, "branch on index high"                 },
  { "bxle"  , 0x87, MASK       , INSTR_RS_RRRD   , R_ANAL_OP_TYPE_NULL  , 0, "branch on index low or equal"         },
  { "c"     , 0x59, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_CMP   , 0, "compare"                              },
  { "ch"    , 0x49, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_CMP   , 0, "compare halfword"                     },
  { "cl"    , 0x55, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_CMP   , 0, "compare logical"                      },
  { "clc"   , 0xD5, MASK       , INSTR_SS_L0RDRD , R_ANAL_OP_TYPE_CMP   , 0, "compare logical character"            },
  { "cli"   , 0x95, MASK       , INSTR_SI_URD    , R_ANAL_OP_TYPE_CMP   , 0, "compare logical immediate"            },
  { "clm"   , 0xF5, MASK       , INSTR_SS_LLRDRD , R_ANAL_OP_TYPE_CMP   , 0, "compare logical memory"               },
  { "clr"   , 0x15, MASK       , INSTR_RR_RR     , R_ANAL_OP_TYPE_CMP   , 0, "compare logical register"             },
  { "cm"    , 0xF9, MASK       , INSTR_SS_LLRDRD , R_ANAL_OP_TYPE_CMP   , 0, "compare memory"                       },
  { "cr"    , 0x19, MASK       , INSTR_RR_RR     , R_ANAL_OP_TYPE_CMP   , 0, "compare register"                     },
  { "dm"    , 0x85, MASK       , INSTR_RS_RRRD   , R_ANAL_OP_TYPE_DIV   , 0, "divide memory"                        },
  { "ex"    , 0x44, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_NULL  , 0, "execute"                              },
  { "ic"    , 0x43, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_NULL  , 0, "insert character"                     },
  { "im"    , 0x9D, MASK       , INSTR_SI_URD    , R_ANAL_OP_TYPE_NULL  , 0, "immediate in memory"                  },
  { "iso"   , 0x82, MASK       , INSTR_RX_0RRD   , R_ANAL_OP_TYPE_NULL  , 0, "iso (ascii) test"                     },
  { "l"     , 0x58, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_LOAD  , 0, "load"                                 },
  { "la"    , 0x41, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_LEA   , 0, "load address"                         },
  { "lc"    , 0x53, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_CPL   , 0, "load complement"                      },
  { "lcr"   , 0x13, MASK       , INSTR_RR_RR     , R_ANAL_OP_TYPE_CPL   , 0, "load complement register"             },
  { "lh"    , 0x48, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_LOAD  , 0, "load halfword"                        },
  { "lm"    , 0x98, MASK       , INSTR_RS_RRRD   , R_ANAL_OP_TYPE_LOAD  , 0, "load multiple"                        },
  { "ln"    , 0x51, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_CPL   , 0, "load negative"                        },
  { "lnr"   , 0x11, MASK       , INSTR_RR_RR     , R_ANAL_OP_TYPE_CPL   , 0, "load negative register"               },
  { "lpr"   , 0x10, MASK       , INSTR_RR_RR     , R_ANAL_OP_TYPE_ABS   , 0, "load positive register (absolute)"    },
  { "lr"    , 0x18, MASK       , INSTR_RR_RR     , R_ANAL_OP_TYPE_MOV   , 0, "load register"                        },
  { "lt"    , 0x52, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_LOAD  , 0, "load and test"                        },
  { "ltr"   , 0x12, MASK       , INSTR_RR_RR     , R_ANAL_OP_TYPE_LOAD  , 0, "load and test register"               },
  { "mlh"   , 0x83, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_MUL   , 0, "multiply logical halfword"            },
  { "mlr"   , 0x26, MASK       , INSTR_RR_RR     , R_ANAL_OP_TYPE_MUL   , 0, "multiply logical register"            },
  { "mvc"   , 0xD2, MASK       , INSTR_SS_L0RDRD , R_ANAL_OP_TYPE_NULL  , 0, "move character(s)"                    },
  { "mvcr"  , 0xF2, MASK       , INSTR_SS_0RDRD  , R_ANAL_OP_TYPE_NULL  , 0, "move character(s) register"           },
  { "mvi"   , 0x92, MASK       , INSTR_SI_URD    , R_ANAL_OP_TYPE_NULL  , 0, "move immediate"                       },
  { "mvn"   , 0xD1, MASK       , INSTR_SS_L0RDRD , R_ANAL_OP_TYPE_NULL  , 0, "move nibbles"                         },
  { "mvo"   , 0xF1, MASK       , INSTR_SS_LLRDRD , R_ANAL_OP_TYPE_NULL  , 0, "move with offset"                     },
  { "mvz"   , 0xD3, MASK       , INSTR_SS_L0RDRD , R_ANAL_OP_TYPE_NULL  , 0, "move zones"                           },
  { "n"     , 0x54, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_AND   , 0, "and"                                  },
  { "nc"    , 0xD4, MASK       , INSTR_SS_L0RDRD , R_ANAL_OP_TYPE_AND   , 0, "and character"                        },
  { "ni"    , 0x94, MASK       , INSTR_SI_URD    , R_ANAL_OP_TYPE_AND   , 0, "and immediate"                        },
  { "nr"    , 0x14, MASK       , INSTR_RR_RR     , R_ANAL_OP_TYPE_AND   , 0, "and register"                         },
  { "o"     , 0x56, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_OR    , 0, "or"                                   },
  { "oc"    , 0xD6, MASK       , INSTR_SS_LLRDRD , R_ANAL_OP_TYPE_OR    , 0, "or character"                         },
  { "oi"    , 0x96, MASK       , INSTR_SI_URD    , R_ANAL_OP_TYPE_OR    , 0, "or immediate"                         },
  { "or"    , 0x16, MASK       , INSTR_RR_RR     , R_ANAL_OP_TYPE_OR    , 0, "or register"                          },
  { "s"     , 0x5B, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_SUB   , 0, "substract"                            },
  { "sh"    , 0x4B, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_SUB   , 0, "subtract halfword"                    },
  { "sl"    , 0x5F, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_SUB   , 0, "subtract logical"                     },
  { "sla"   , 0x02, MASK       , INSTR_RR_UR     , R_ANAL_OP_TYPE_SAL   , 0, "shift left algebraic"                 },
  { "sll"   , 0x04, MASK       , INSTR_RR_UR     , R_ANAL_OP_TYPE_SHL   , 0, "shift left logical"                   },
  { "slm"   , 0xF4, MASK       , INSTR_SS_LLRDRD , R_ANAL_OP_TYPE_SUB   , 0, "subtract logical memory"              },
  { "slr"   , 0x1F, MASK       , INSTR_RR_RR     , R_ANAL_OP_TYPE_SUB   , 0, "subtract logical register"            },
  { "slri"  , 0x0C, MASK       , INSTR_RR_UR     , R_ANAL_OP_TYPE_SUB   , 0, "subtract logical register immediate"  },
  { "sm"    , 0xF3, MASK       , INSTR_SS_LLRDRD , R_ANAL_OP_TYPE_SUB   , 0, "subtract memory"                      },
  { "sr"    , 0x1B, MASK       , INSTR_RR_RR     , R_ANAL_OP_TYPE_SUB   , 0, "subtract register"                    },
  { "sra"   , 0x03, MASK       , INSTR_RR_UR     , R_ANAL_OP_TYPE_SAR   , 0, "shift right algebraic"                },
  { "srl"   , 0x08, MASK       , INSTR_RR_UR     , R_ANAL_OP_TYPE_SHR   , 0, "shift right logical"                  },
  { "st"    , 0x50, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_STORE , 0, "store"                                },
  { "stc"   , 0x42, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_STORE , 0, "store charcter"                       },
  { "sth"   , 0x40, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_STORE , 0, "store halfword"                       },
  { "stm"   , 0x90, MASK       , INSTR_RS_RRRD   , R_ANAL_OP_TYPE_STORE , 0, "store multiple"                       },
  { "tm"    , 0x91, MASK       , INSTR_SI_URD    , R_ANAL_OP_TYPE_NULL  , 0, "test under mask"                      },
  { "tr"    , 0xDC, MASK       , INSTR_SS_L0RDRD , R_ANAL_OP_TYPE_NULL  , 0, "translate"                            },
  { "trt"   , 0xD0, MASK       , INSTR_SS_L0RDRD , R_ANAL_OP_TYPE_NULL  , 0, "translate and test"                   },
  { "x"     , 0x57, MASK       , INSTR_RX_RRRD   , R_ANAL_OP_TYPE_XOR   , 0, "exclusive or"                         },
  { "xc"    , 0xD7, MASK       , INSTR_SS_LLRDRD , R_ANAL_OP_TYPE_XOR   , 0, "exclusive or character"               },
  { "xi"    , 0x97, MASK       , INSTR_SI_URD    , R_ANAL_OP_TYPE_XOR   , 0, "exclusive or immediate"               },
  { "xr"    , 0x17, MASK       , INSTR_RR_RR     , R_ANAL_OP_TYPE_XOR   , 0, "exclusive or register"                },
  { "asa"   , 0x23, MASK       , INSTR_RR_RR     , R_ANAL_OP_TYPE_NULL  , 0, "allocate stack area"                  },
  { "fsa"   , 0x22, MASK       , INSTR_RR_RR     , R_ANAL_OP_TYPE_LEAVE , 0, "free stack area"                      },
  { "cbs"   , 0xDB, MASK       , INSTR_SS_L0RDRD , R_ANAL_OP_TYPE_NULL  , 0, "binary to iso (ascii) conversion"     },
  { "csbh"  , 0xF6, MASK       , INSTR_SS_0LRDRD , R_ANAL_OP_TYPE_NULL  , 0, "iso (ascii) to binary conversion"     },
  { "dis"   , 0xF8, MASK       , INSTR_SS_LLRDRD , R_ANAL_OP_TYPE_NULL  , 0, "dicotomic search"                     },
  { "lie"   , 0x99, MASK       , INSTR_SI_URD    , R_ANAL_OP_TYPE_NULL  , 0, "look for immediate equal"             },
  { "line"  , 0x9B, MASK       , INSTR_SI_URD    , R_ANAL_OP_TYPE_NULL  , 0, "look for immediate not equal"         },
  { "ses"   , 0xF7, MASK       , INSTR_SS_LLRDRD , R_ANAL_OP_TYPE_NULL  , 0, "sequential search"                    },
  { "sesm"  , 0xF0, MASK       , INSTR_SS_LLRDRD , R_ANAL_OP_TYPE_NULL  , 0, "sequential search with mask"          },
  { "call"  , 0x9A, MASK       , INSTR_SS_NBD    , R_ANAL_OP_TYPE_CALL  , 0, "subroutine call"                      },
  { "rets"  , 0x20, MASK       , INSTR_RR_U0     , R_ANAL_OP_TYPE_RET   , 0, "subroutine return"                    },
  // ??            ACT       active module	 
  { "calexs", 0x9c, MASK       , INSTR_SS_NBD    , R_ANAL_OP_TYPE_CALL  , 0, "call external system module"          },
  // ??            CALEXT    call external	 
  { "retext", 0x28, MASK       , INSTR_RR_U0     , R_ANAL_OP_TYPE_RET   , 0, "return from external module"          }, // RR_U0 is guess
  // ??            RLSEM     release module	 
  { "svc"   , 0x0a, MASK       , INSTR_RR_U0     , R_ANAL_OP_TYPE_SWI   , 0, "supervisor call"                      },
  { "??21"  , 0x21, MASK       , INSTR_RR_U0     , R_ANAL_OP_TYPE_UNK   , 0, "test io?"                             },
  { "??0b"  , 0x0b, MASK       , INSTR_RR_RR     , R_ANAL_OP_TYPE_UNK   , 0, "unknown"                              },
  { "??93"  , 0x93, MASK       , INSTR_SI_URD    , R_ANAL_OP_TYPE_UNK   , 0, "start io?"                            },
  { "??4e"  , 0x4e, MASK       , INSTR_RS_RRRD   , R_ANAL_OP_TYPE_UNK   , 0, "unknown"                              }, // RS is guess
  { "??4f"  , 0x4f, MASK       , INSTR_RS_RRRD   , R_ANAL_OP_TYPE_UNK   , 0, "unknown"                              }, // RS is guess
  { NULL    , 0   , 0          , 0               , 0                    , 0,  ""}
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

static struct p6060_opcode* p6060_mnemonic(RStrBuf *op_buf, int* op_size, const ut8 *b)
{
  int n;
  struct p6060_opcode* opc = opcode[b[0]];
  *op_size = 1;
  if (!opc) {
    r_strbuf_set (op_buf, "invalid");
    return NULL;
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
  r_strbuf_set (op_buf, opc->name);
  r_strbuf_append (op_buf, " ");
  switch(opc->format) {
    case INSTR_RR_RR:
      r_strbuf_appendf (op_buf, "r%d, r%d", MSN(b,1), LSN(b,1));
      *op_size = 2;
      break;
    case INSTR_RR_0R:
      r_strbuf_appendf (op_buf, "r%d", LSN(b,1));
      *op_size = 2;
      break;
    case INSTR_RR_U0:
      r_strbuf_appendf (op_buf, "%d", b[1]);
      *op_size = 2;
      break;
    case INSTR_RR_UR:
      r_strbuf_appendf (op_buf, "r%d, %d", LSN(b,1), MSN(b,1));
      *op_size = 2;
      break;
    case INSTR_RR_MR:
      r_strbuf_appendf (op_buf, "%d, r%d", MSN(b,1), LSN(b,1));
      *op_size = 2;
      break;
    case INSTR_RX_RRRD:
      r_strbuf_appendf (op_buf, "r%d, ", MSN(b,1));
      disp_rrd(op_buf, LSN(b,1), b, 2);
      *op_size = 4;
      break;
    case INSTR_RX_0RRD:
      disp_rrd(op_buf, LSN(b,1), b, 2);
      *op_size = 4;
      break;
    case INSTR_RX_MRRD:
      r_strbuf_appendf (op_buf, "%d, ", MSN(b,1));
      disp_rrd(op_buf, LSN(b,1), b, 2);
      *op_size = 4;
      break;
    case INSTR_RS_RRRD:
      r_strbuf_appendf (op_buf, "r%d, r%d, ", MSN(b,1), LSN(b,1));
      disp_rd(op_buf, b, 2);
      *op_size = 4;
      break;
    case INSTR_SI_URD:
      disp_rd(op_buf, b, 2);
      r_strbuf_appendf (op_buf, ", %d", b[1]);
      *op_size = 4;
      break;
    case INSTR_SS_LLRDRD:
      disp_lrd(op_buf, MSN(b,1), b, 2);
      r_strbuf_append (op_buf, ", ");
      disp_lrd(op_buf, LSN(b,1), b, 4);
      *op_size = 6;
      break;
    case INSTR_SS_L0RDRD:
      disp_lrd(op_buf, b[1], b, 2);
      r_strbuf_append (op_buf, ", ");
      disp_rd(op_buf, b, 4);
      *op_size = 6;
      break;
    case INSTR_SS_0RDRD:
      disp_rd(op_buf, b, 2);
      r_strbuf_append (op_buf, ", ");
      disp_rd(op_buf, b, 4);
      *op_size = 6;
      break;
    case INSTR_SS_0LRDRD:
      disp_rd(op_buf, b, 2);
      r_strbuf_append (op_buf, ", ");
      disp_lrd(op_buf, LSN(b,1), b, 4);
      *op_size = 6;
      break;
    case INSTR_SS_NBD:
      n = b[1] & 0x1f;
      *op_size = 4 + 2*n;
      disp_rd(op_buf, b, 2);
      for (int i = 1; i <= n; i++) {
	r_strbuf_append (op_buf, ", ");
	disp_rd(op_buf, b, 2+2*i);
      }
      break;
    case INVALID:
      break;
  }
  return opc;
}
