// See LICENSE for license details.

#include "tag.h"
#include "debugprint.h"
#include "decode.h"
#include "trap.h"
#include "common.h"
#include "config.h"
#include "processor.h"
#include "pmp.h"
#include <vector>
#include <assert.h>

tag_t::tag_t(processor_t* proc, size_t tag_width)
 : proc(proc)
{
  if (tag_width < 1 || tag_width > 64)
  {
    tag_width_ = 2;
    debug_crit("Tag width can only be between 1 and 64bit! Set to 2 (default)\n");
    assert(false);
  }
  else
    tag_width_ = tag_width;
  debug_info("Tag width: %zu\n", tag_width);
  debug_info("sizeof reg_t: %zu\n", sizeof(reg_t));
}

tag_t::~tag_t()
{
}

void tag_t::reset()
{
  tags_list_.clear();
}

void tag_t::store_tag(reg_t addr, uint64_t val)
{
  if (proc->xlen == 32) {
    addr = (uint32_t)addr;
  }
  if (proc && proc->get_pmp()->isactive()) {
    if(proc->get_state()->sec_level != S_SECURE &&
      proc->get_state()->prv != PRV_M) {
      uint64_t oldtag = load_tag(addr);
      if (oldtag != T_NORMAL || val != T_NORMAL) {
        debug_warn("Normal-mode @ %p can only store N tags\n", (void*)proc->get_state()->pc);
        throw trap_illegal_instruction(0);
      }
    }
    if (proc->get_state()->prv == PRV_U) {
      /* UT can only overwrite tags N and UT */
      uint64_t oldtag = load_tag(addr);
      if (oldtag != T_NORMAL && oldtag != T_UTRUSTED) {
        debug_warn("UT @ %p tried to overwrite %zu but can only overwrite N and UT tags!\n", (void*)proc->get_state()->pc, oldtag);
        throw trap_illegal_instruction(0);
      }
      /* UT can only write tags N and UT */
      if (val != T_NORMAL && val != T_UTRUSTED) {
        debug_warn("UT @ %p tried to write %zu but can only write N and UT tags!\n", (void*)proc->get_state()->pc, val);
        throw trap_illegal_instruction(0);
      }
    }
  }
  if (tag_width_ != 64) {
    val = val % (1 << tag_width_);
  }
  addr = TAG_ADDR_ALIGN(addr);
  tags_list_[addr] = val;
  debug_verbose("STORE_TAG @ %p accessing %p. Tag %lu\n", (void*)proc->get_state()->pc, addr, val);
}

uint64_t tag_t::load_tag(reg_t addr)
{
  if (proc->xlen == 32) {
    addr = (uint32_t)addr;
  }
  addr = TAG_ADDR_ALIGN(addr);
  if (tags_list_.find(addr) != tags_list_.end()) {
    return tags_list_[addr];
  }
  return TAG_NOT_FOUND;
}

typedef enum {
  R = 1<<LOAD,
  W = 1<<STORE,
  X = 1<<FETCH,
} access_t;

uint8_t access_matrix[4][4] = {
/*       to  NORMAL CALLABLE UTRUSTED STRUSTED */
/*from UN*/ {R|W|X, X,       0,       0},
     /*SN*/ {R|W|X, X,       0,       0},
     /*UT*/ {R|W|X, R|X,     R|W|X,   0},
     /*ST*/ {R|W|X, R|W|X,   R|W,     R|W|X},
};

/**
 * Check if tag of accessed memory meets access policy.
 * If type is FETCH, this function in addition performs optional
 * vertical mode switches.
 *
 * @param addr The accessed address
 * @param type The type of access, one of FETCH | READ | WRITE
 * @return false on error
 */
bool tag_t::tagcheck(reg_t addr, access_type type) {
  if (!proc || !proc->get_pmp()->isactive()) {
    return true;
  }
  security_type_t secure = proc->get_state()->sec_level;
  reg_t prv = proc->get_state()->prv;
  if (prv == PRV_M) {
    /* Machine-mode bypasses all tag checks */
    return true;
  }
  uint8_t mode = (prv == PRV_S) | (secure << 1);
  uint64_t tag = load_tag(addr);
  assert(mode <= 3);
  assert(tag <= 3);
  //debug_printf("Tag access check @ %p. Type %d, mode %d, tag %d, access %d!\n", (void*)proc->get_state()->pc, type, mode, (int)tag, access_matrix[mode][tag]);
  if(!(access_matrix[mode][tag] & (1<<type))) {
    debug_warn("Tag access violation @ %p-->%p. AccType %d, prv %d, secure %d, mode %d, tag %d, access %d!\n", (void*)proc->get_state()->pc, (void*)addr, type, prv, secure, mode, (int)tag, access_matrix[mode][tag]);
    return false;
  }
  if (type == FETCH) {
    return trusted_modeswitch(secure, prv, tag);
  } else {
    return true;
  }
}

/**
 * Test for and perform vertical mode switches
 * @param secure The vertical security mode (S_NORMAL | S_SECURE)
 * @param prv The horizontal privilege mode
 * @param tag The tag to check against
 * @return true on success
 */
bool tag_t::trusted_modeswitch(security_type_t secure, reg_t prv, uint64_t tag) {
  if (secure == S_NORMAL) {
    if (tag == T_CALLABLE) {
      if (prv == PRV_U) {
        if(!proc->get_pmp()->is_ut_runnable()) { // check tstatus csr
          debug_warn("Modeswitch TRUSTED @ %p fails. TTCB not initialized or interrupted!\n", (void*)proc->get_state()->pc);
          return false;
        }
      }
      proc->get_state()->sec_level = S_SECURE;
      debug_info("Modeswitch TRUSTED @ %p\n", (void*)proc->get_state()->pc);
    }
  } else if (secure == S_SECURE && tag == T_NORMAL) {
    /* We are in UT or MT */
    proc->get_state()->sec_level = S_NORMAL;
    debug_info("Modeswitch NORMAL @ %p\n", (void*)proc->get_state()->pc);
  }
  return true;
}
