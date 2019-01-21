// See LICENSE for license details.

#include "pmp.h"
#include "sim.h"
#include "mmu.h"
#include "tag.h"
#include "processor.h"
#include <assert.h>

pmp_t::pmp_t(sim_t* sim, processor_t* proc)
 : sim(sim), proc(proc)
{
  reset();
}

pmp_t::~pmp_t()
{
}

void pmp_t::reset()
{
  flush_pmp();
  mtstatus.raw = 0;
  current_ttcb_ptr = 0;
}

void pmp_t::flush_pmp()
{
  for (size_t i = 0; i < PMP_ENTRIES; i++) {
    pmpcache[i].base = 0;
    pmpcache[i].bound = (reg_t)-1;
    pmpcache[i].flags.raw = 0;
    pmpcache[i].flags.flags.perm = 0x7; //rwx
  }
}

bool pmp_t::check(reg_t addr, reg_t len, access_type type, reg_t priv, security_type_t stype)
{
  assert(type < PERM_SIZE);

  if (priv == PRV_S) {
    if (type != FETCH) {
      /* S can read/write anything */
      return true;
    }
    if (stype == S_SECURE) {
      /* ST can only fetch if mapped in MPU */
      for (size_t i = 0; i < PMP_ENTRIES; i++) {
        /* addr is covered by pmp entry */
        if ((addr >= pmpcache[i].base) &&
            (addr + len <= pmpcache[i].bound) &&
            /* access type is subset of perm */
            (pmpcache[i].flags.flags.perm & (1 << type))) {
          debug_verbose("ST: matching PMP range[%zu] %016lx - %016lx [%016lx]\n", i, pmpcache[i].base, pmpcache[i].bound, pmpcache[i].flags.raw);
          /* ST requires PMP entry with ST-flag */
          if (pmpcache[i].flags.flags.ST) {
            debug_verbose("matching ST\n");
            return true;
          }
        }
      }
      debug_warn("ST has no valid PMP entry\n");
      return false;
    }
    /* SN can fetch anything (that is allowed by tags) */
    return true;
  } else if (priv == PRV_U) {
    /* PRV_U (UN and UT) both go through the MPU */
    for (size_t i = 0; i < PMP_ENTRIES; i++) {
      /* addr is covered by pmp entry */
      if ((addr >= pmpcache[i].base) &&
          (addr + len <= pmpcache[i].bound) &&
          /* access type is subset of perm */
          (pmpcache[i].flags.flags.perm & (1 << type))) {
          debug_verbose("U: matching PMP range[%zu] %016lx - %016lx [%016lx]\n", i, pmpcache[i].base, pmpcache[i].bound, pmpcache[i].flags.raw);
        /* UT Fetch requires PMP entry with T-flag which is ACK'ed. */
        if ((stype == S_SECURE && type == FETCH) && (!pmpcache[i].flags.flags.T || !pmpcache[i].flags.flags.ACK)) {
          debug_verbose("UT fetch: mismatch in flags!\n");
          continue;
        }
        /* U cannot access ST range */
        if (pmpcache[i].flags.flags.ST) {
          debug_verbose("UT: mismatch with ST!\n");
          continue;
        }
        debug_verbose("U valid: %d,%ld,%ld,%ld\n", stype == S_SECURE, pmpcache[i].flags.flags.T, pmpcache[i].flags.flags.ACK, pmpcache[i].flags.flags.ST);
        return true;
      }
    }
    debug_verbose("UN/UT has no valid PMP entry\n");
    return false;
  }
  assert(false);
}

pmp_entry_t* pmp_t::get_entry(size_t index)
{
  assert(index < PMP_ENTRIES);
  return &pmpcache[index];
}

void pmp_t::set_entry(size_t index, pmp_entry_t entry)
{
  assert(index < PMP_ENTRIES);

  if (this->proc->state.sec_level == S_NORMAL &&
      this->proc->state.prv == PRV_S) {
    /* SN automatically clears acknowledge */
    entry.flags.flags.ACK = 0;
    /* SN cannot write ST flag or overwrite existing ST entry */
    if (entry.flags.flags.ST) {
      debug_warn("Cannot (over)write PMP.ST entry from SN @ %p! Ignoring it.\n", (void*)this->proc->state.pc);
      return;
    }
  }
  pmpcache[index] = entry;
}

reg_t pmp_t::get_mtstatus() {
  uint32_t v = mtstatus.raw;
  /* set read-only fields */
  /* mode */
  v = set_field(v, TSTATUS_MO, proc->state.sec_level == S_SECURE);
  return v;
}

bool pmp_t::is_ut_runnable() {
  return mtstatus.ue && !mtstatus.ui;
}

void pmp_t::set_mtstatus(uintptr_t status) {
  reg_t oldmode = mtstatus.mode; /* mode is not writable */
  mtstatus.raw = status;
  mtstatus.mode = oldmode;
}

bool pmp_t::isactive() {
  return mtstatus.en;
}

void pmp_t::notify_interrupt() {
  if (isactive() && proc->state.sec_level == S_SECURE &&
      proc->state.prv == PRV_U && is_ut_runnable()) {
    debug_warn("Interrupted running enclave @ %p\n", (void*)proc->get_state()->pc);
    mtstatus.ui = 1;
  }
}

void pmp_t::update_ttcb(uintptr_t new_ttcb) {
  current_ttcb_ptr = new_ttcb;
}

void pmp_t::nack_all() {
  for (size_t i = 0; i < PMP_ENTRIES; i++) {
    pmpcache[i].flags.flags.ACK = 0;
  }
}
