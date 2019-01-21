// See LICENSE for license details.

#ifndef _RISCV_PMP_H
#define _RISCV_PMP_H

#include "decode.h"
#include "trap.h"
#include "common.h"
#include "config.h"
#include "sim.h"
#include "processor.h"
#include "memtracer.h"
#include "debugprint.h"
#include <stdlib.h>
#include <vector>

#define PERM_SIZE 3

typedef struct __attribute__((packed)) {
  reg_t perm : PERM_SIZE;
  reg_t T : 1;
  reg_t ACK : 1;
  reg_t ST : 1;
  reg_t unused : 2;
} pmp_flags_t;

typedef struct __attribute__((packed)) {
  reg_t base;
  reg_t bound;
  union {
    reg_t raw;
    pmp_flags_t flags;
  } flags;
} pmp_entry_t;

typedef union __attribute__((packed)) {
  struct {
    reg_t en : 1;
    reg_t mode : 1;
    reg_t reserved : 14;
    reg_t ue : 1;
    reg_t ui : 1;
  };
  reg_t raw;
} mtstatus_t;

typedef struct __attribute__((packed)) {
  reg_t init : 1;
  reg_t running : 1;
  reg_t tid_valid : 1;
  reg_t interrupted : 1;
  reg_t unused : 4;
} ttcb_status_t;

class pmp_t
{
public:
  pmp_t(sim_t* sim, processor_t* proc);
  ~pmp_t();
  void reset();

  static const reg_t PMP_ENTRIES = 8;

  void flush_pmp();
  void nack_all();

  bool check(reg_t addr, reg_t len, access_type type, reg_t priv, security_type_t stype);
  pmp_entry_t* get_entry(size_t index);
  void set_entry(size_t index, pmp_entry_t entry);
  reg_t get_mtstatus();
  bool isactive();
  void notify_interrupt();
  void set_mtstatus(uintptr_t status);
  bool is_ut_runnable();
  void update_ttcb(uintptr_t new_ttcb);

private:
  sim_t* sim;
  processor_t* proc;

  uintptr_t current_ttcb_ptr;
  mtstatus_t mtstatus;
  pmp_entry_t pmpcache[PMP_ENTRIES];

  friend class processor_t;
  friend class mmu_t;
};

#endif
