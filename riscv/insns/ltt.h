WRITE_REG(insn.rd(), (insn.it_etag() - TAG.load_tag(RS1 + insn.it_imm())));
