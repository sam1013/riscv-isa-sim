REQUIRE_TAG(RS1 + insn.it_imm(), insn.it_etag());
WRITE_RD(MMU.load_int8(RS1 + insn.it_imm()));
