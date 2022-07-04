/* radare - LGPL - Copyright 2015 - condret */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

// TODO use flag to mark rX as PC-relative? How to access flags? Flag space?
// anal.flb (RFlagBind), anal.flg_class_set/get, flg_fcn_set

#include "p6060_opc.h"

static int p6060_anop(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
  RStrBuf* op_buf = r_strbuf_new("");
  struct p6060_opcode* opc = p6060_mnemonic (op_buf, &op->size, data);
  if (!opc) {
    return -1;
  }
  op->mnemonic = r_strbuf_drain (op_buf);
  memset (op, '\0', sizeof (RAnalOp));
  op->addr = addr;
  op->type = R_ANAL_OP_TYPE_UNK;
  // op->type = R_ANAL_OP_TYPE_NOP;
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
    .set_reg_profile = NULL,
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

