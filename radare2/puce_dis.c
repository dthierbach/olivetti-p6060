// ln -s `pwd`/puce_dis.so ~/.local/share/radare2/plugins/

#include <r_asm.h>
#include <r_lib.h>
#include <r_anal.h>

static bool puce_init(void *user) {
  return true; // true = successful init??
}

static int puce_disassemble (RAsm *a, RAsmOp *op, const ut8 *b, int l)
{
  int x = b[0] & 0xf;
  int y = b[1] >> 4;
  int z = b[1] & 0xf;
  op->size = 2;
  int f = b[0];
  if (f & 0x80) {
    if (f == 0xA8) {
      r_strbuf_set (&op->buf_asm, "AMI ");
    } else if (f == 0x88) {
      r_strbuf_set (&op->buf_asm, "AMIP");
    } else if (f == 0xc8) {
      r_strbuf_set (&op->buf_asm, "REDI");
    } else if (f == 0xc9) {
      r_strbuf_set (&op->buf_asm, "SEDI");
    } else if (f == 0x90) {
      r_strbuf_set (&op->buf_asm, "!!RESET");
    } else if (f == 0xf0) {
      r_strbuf_set (&op->buf_asm, "!!ALFA ");
    } else {
      r_strbuf_set (&op->buf_asm, "??");
      r_strbuf_appendf (&op->buf_asm, "%02x", f & 0x7f);
    }
    r_strbuf_appendf (&op->buf_asm, " %1x,%1x", y, z);
  } else {
    // jump
    r_strbuf_set (&op->buf_asm, "??");
    r_strbuf_appendf (&op->buf_asm, "%1x_", f >> 4);
    r_strbuf_appendf (&op->buf_asm, " %1x,%02x", x, b[1]);
  }
  return op->size;
}

RAsmPlugin r_asm_plugin_puce = {
	.name = "puce",
	.desc = "Olivetti PUCE TTL CPU disassembler",
	.arch = "puce",
	.license = "LGPL3",
	.bits = 16,
	.endian = R_SYS_ENDIAN_BIG,
	.init = &puce_init,
	.disassemble = &puce_disassemble,
	.modify = NULL,
	.assemble = NULL,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
        .type = R_LIB_TYPE_ASM,
        .data = &r_asm_plugin_puce,
	.version = R2_VERSION
};
#endif
