REQUIRE_TAG(RS1 + insn.it_imm(), insn.it_etag());
WRITE_RD(MMU.load_int16(RS1 + insn.it_imm()));
