/* example r_asm plugin by pancake at 2014 */

#include <r_asm.h>
#include <r_lib.h>

#include "p6060_opc.h"

static int p6060_disassemble (RAsm *a, RAsmOp *op, const ut8 *b, int l)
{
  op->size = p6060_mnemonic (&op->buf_asm, b);
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
