reg_t tmp = npc;
set_pc_direct(JUMP_TARGET);
WRITE_RD(tmp);
