require_rv64;
REQUIRE_TAG(RS1 + insn.st_imm(), insn.st_etag());
MMU.store_uint64(RS1 + insn.st_imm(), RS2);
TAG.store_tag(RS1 + insn.st_imm(), insn.st_ntag());
