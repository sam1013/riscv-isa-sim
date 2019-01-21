// See LICENSE for license details.

#ifndef _RISCV_DEBUGPRINT_H
#define _RISCV_DEBUGPRINT_H

#define DEBUG_CRIT     0
#define DEBUG_WARN     1
#define DEBUG_INFO     2
#define DEBUG_VERBOSE  3

#define debug_crit(...) debugprint_t::debugprintf(DEBUG_CRIT, __VA_ARGS__)
#define debug_warn(...) debugprint_t::debugprintf(DEBUG_WARN, __VA_ARGS__)
#define debug_info(...) debugprint_t::debugprintf(DEBUG_INFO, __VA_ARGS__)
#define debug_verbose(...) debugprint_t::debugprintf(DEBUG_VERBOSE, __VA_ARGS__)

class debugprint_t
{
public:
  static void set_debuglevel(int level);
  static int debugprintf(int level, const char* fmt...);

private:
  debugprint_t();
  ~debugprint_t();
  static int debuglevel;
};

#endif
