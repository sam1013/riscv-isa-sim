// See LICENSE for license details.

#ifndef TAG_H
#define TAG_H

#include "config.h"
#include "processor.h"
#include "memtracer.h"
#include <vector>

enum tag_type {
  T_NORMAL = 0,
  T_CALLABLE = 1,
  T_UTRUSTED = 2,
  T_STRUSTED = 3
};

#define TAG_WIDTH 4
#define TAG_GRANULARITY (proc->xlen/8)         /* Must be power of 2. Granularity is one tag per word */
#define TAG_ADDR_ALIGN(addr) ((addr / TAG_GRANULARITY) * TAG_GRANULARITY)
#define TAG_NOT_FOUND T_NORMAL

class tag_t
{
public:
  tag_t(processor_t* proc, size_t tag_width);
  ~tag_t();
  void reset();

  bool check_pmp(reg_t addr, reg_t len, access_type type);
  bool trusted_modeswitch(security_type_t secure, reg_t prv, uint64_t tag);
  bool tagcheck(reg_t addr, access_type type);
  bool fetch_tagcheck(reg_t addr);
  bool loadstore_tagcheck(reg_t addr);

  void store_tag(reg_t addr, uint64_t val);
  uint64_t load_tag(reg_t addr);

private:
  processor_t* proc;
  std::map<reg_t, uint64_t> tags_list_;
  size_t tag_width_;

  friend class processor_t;
};

#endif
