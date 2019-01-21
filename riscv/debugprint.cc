// See LICENSE for license details.

#include <cstdarg>
#include <stdio.h>
#include "debugprint.h"

void debugprint_t::set_debuglevel(int level) {
  debuglevel = level;
}

int debugprint_t::debugprintf(int level, const char *fmt...) {
  if (debuglevel >= level) {
    printf("\x1b[32m[SPIKE]\x1b[0m ");
    va_list args;
    va_start(args, fmt);
    return vprintf(fmt, args);
  }
  return 0;
}

int debugprint_t::debuglevel = 0;
