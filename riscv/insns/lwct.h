REQUIRE_TAG(RS1 + insn.it_imm(), insn.it_etag());
WRITE_RD(MMU.load_int32(RS1 + insn.it_imm()));
