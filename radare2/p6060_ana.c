/* radare - LGPL - Copyright 2015 - condret */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include <r_util.h>

// TODO use flag to mark rX as PC-relative? How to access flags? Flag space?
// anal.flb (RFlagBind), anal.flg_class_set/get, flg_fcn_set

#include "p6060_opc.h"

typedef ut64 using_t[16];

static bool set_reg_profile(RAnal *anal) {
  const char *p =
/*
    "=PC	pc\n"
    "=LR	r14\n"
    "=SP	r13\n"
    "=BP	r12\n"
    "=A0	r0\n"
    "=A1	r1\n"
    "=A2	r2\n"
    "=A3	r3\n"
    "=SN	r0\n"
    "gpr	sb	.32	36	0\n" // r9
    "gpr	sl	.32	40	0\n" // rl0
    "gpr	fp	.32	44	0\n" // r11
    "gpr	ip	.32	48	0\n" // r12
    "gpr	sp	.32	52	0\n" // r13
    "gpr	lr	.32	56	0\n" // r14
    "gpr	pc	.32	60	0\n" // r15
*/
    "=PC	pc\n"
    "=SP	r13\n"
    "=A0	r0\n"
    "gpr	r0	.32	0	0\n"
    "gpr	r1	.32	4	0\n"
    "gpr	r2	.32	8	0\n"
    "gpr	r3	.32	12	0\n"
    "gpr	r4	.32	16	0\n"
    "gpr	r5	.32	20	0\n"
    "gpr	r6	.32	24	0\n"
    "gpr	r7	.32	28	0\n"
    "gpr	r8	.32	32	0\n"
    "gpr	r9	.32	36	0\n"
    "gpr	r10	.32	40	0\n"
    "gpr	r11	.32	44	0\n"
    "gpr	r12	.32	48	0\n"
    "gpr	r13	.32	52	0\n"
    "gpr	r14	.32	56	0\n"
    "gpr	r15	.32	60	0\n"
    "gpr	pc	.32	64	0\n"
    ;
  return r_reg_set_profile_string (anal->reg, p);
}

static void anal_using(RAnalOp *op, const ut8* data) 
{
  int reg1 = MSN(data,1);
  int reg2 = LSN(data,1);
  if (reg2 == 0) {
    op->type = R_ANAL_OP_TYPE_LEA;
    op->ptr = op->addr + 2;
  } else {
    op->type = R_ANAL_OP_TYPE_RCALL;
  }
}

static void anal_rrd(RAnalOp *op, using_t using, int reg_index, const ut8 *data, int n)
{
  int reg_base = MSN(data,n);
  ut64 disp = (LSN(data,n) << 8) | data[n+1];
  if (reg_base == 0 && using[reg_index] != 0) {
    op->ptr = using[reg_index] + disp;
    // op->ptrsize
  } else 
  if (reg_index == 0 && using[reg_base] != 0) {
    op->ptr = using[reg_base] + disp;
    // op->ptrsize
  }
}

static void anal_rd(RAnalOp *op, using_t using, const ut8 *data)
{
  int reg_base = MSN(data,0);
  ut64 disp = (LSN(data,0) << 8) | data[1];
  if (using[reg_base] != 0)
  {
    op->ptr = using[reg_base] + disp;
    // op->ptrsize
  }
}

static int p6060_anop(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
  // printf(">>>>> mask=%02x %p\n", mask, data);
  // RSpace "using"
  // r_flag_foreach_space(flag, space, callback, NULL)
  // R_API void r_flag_foreach_range(RFlag *f, ut64 from, ut64 to, RFlagItemCb cb, void *user);

  static p6060_state state; // should put this in "user" (?)

  RFlag* flag = anal->flb.f;
  RSpace* space = r_spaces_get(&flag->spaces, "using");
  RSkipListNode *it, *tmp1;
  RFlagsAtOffset *flags_at;
  RListIter *it2, *tmp2;
  RFlagItem *fi;
  using_t using;
  // slow, iterates over each.
  for (int i = 0; i < 16; i++) {
    using[i] = 0;
  }
  if (space) {
    r_skiplist_foreach_safe (flag->by_off, it, tmp1, flags_at)
    {
      if (flags_at)
      {
	r_list_foreach_safe (flags_at->flags, it2, tmp2, fi)
	{
	  if (fi->space == space && fi->offset <= addr && fi->offset + fi->size >= addr) 
	  {
	    char* prefix = "using.r";
	    char* s = strstr(fi->realname, prefix);
	    if (s) 
	    {
	      s += strlen(prefix);
	      int using_reg = atoi(s);
	      s = strstr(s, "_");
	      s += 1;
	      using[using_reg] = strtol(s, NULL, 16);
	    }
	  }
	}
      }
    }
  }
  RStrBuf* op_buf = r_strbuf_new("");
  int op_size = 0;
  p6060_opcode* opc = 
    p6060_mnemonic (&state, op_buf, &op_size, addr, data);
  memset (op, '\0', sizeof (RAnalOp));
  op->size = op_size;
  op->mnemonic = r_strbuf_drain (op_buf);
  op->addr = addr;
  op->type = R_ANAL_OP_TYPE_ILL;
  // op->val = immediate val
  // op->stackptr
  // op->refptr
  // op->src[3]
  // op->dst
  // op->reg = destination register
  // op->ireg = register for indirect memory
  // op->disp = displacement?
  // vliw = begin of opcode block - use for call??
  if (!opc) {
    return -1;
  }
  op->type = opc->type;
  if (opc->type == R_ANAL_OP_TYPE_UCALL) {
    anal_using(op, data);
  }
  op->cond = opc->cond;
  switch (opc->format) {
    case INSTR_YY_RD:
      anal_rd(op, using, data);
      break;
    case INSTR_RX_RRRD:
    case INSTR_RX_0RRD:
    case INSTR_RX_MRRD:
      anal_rrd(op, using, LSN(data,1), data, 2);
      break;
    case INSTR_RS_RRRD:
      anal_rrd(op, using, 0, data, 2);
      break;
    case INSTR_SI_URD:
      anal_rrd(op, using, 0, data, 2);
      break;
    case INSTR_SS_LLRDRD:
    case INSTR_SS_L0RDRD:
    case INSTR_SS_0RDRD:
    case INSTR_SS_0LRDRD:
      anal_rrd(op, using, 0, data, 4);
      anal_rrd(op, using, 0, data, 2);
      break;
    case INSTR_SS_NBD:
      anal_rrd(op, using, 0, data, 2);
    default:
      break;
  }
  if (opc->type == R_ANAL_OP_TYPE_CALL || opc->type == R_ANAL_OP_TYPE_UCALL) {
    op->jump = op->ptr;
  }
  if (opc->mask == MASK_BC) {
    op->fail = op->addr + op->size;
    op->jump = op->ptr;
  }
  return op->size;
}

static int p6060_anal_init(void *user) {
  p6060_init(user);
  return 1;
}

// bb = basic block
// fcn = ?

struct r_anal_plugin_t r_anal_plugin_p6060 = {
  .name = "p6060",
  .desc = "Olivetti P6060 analysis plugin",
  .arch = "p6060",
  .license = "LGPL3",
  .bits = 32,
  .init = &p6060_anal_init,
  .fini = NULL,
  .op = &p6060_anop,
  .set_reg_profile = &set_reg_profile,
  .fingerprint_bb = NULL,
  .fingerprint_fcn = NULL,
  .diff_bb = NULL,
  .diff_fcn = NULL,
  .diff_eval = NULL
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
  .type = R_LIB_TYPE_ANAL,
  .data = &r_anal_plugin_p6060,
  .version = R2_VERSION
};
#endif

