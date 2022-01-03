#pragma once

#include <sbi/sbi_console.h>
#define DEBUG_MODE 0
#define DEBUG_CTX_SWITCH 0

#if DEBUG_MODE
  #define DEBUG(msg, ...) \
    sbi_printf("[DEBUG] " msg " (%s:%d)\r\n", ## __VA_ARGS__, __FILE__, __LINE__);
#else
  #define DEBUG(msg, ...) \
    ;
#endif

inline void debug_dump_scsrs() {
  if (!DEBUG_MODE)
    return;

  sbi_printf("sstatus [%016lx] sie  [%016lx] sip   [%016lx]\n",
      csr_read(sstatus), csr_read(sie), csr_read(sip));
  sbi_printf("scause  [%016lx] sepc [%016lx] stval [%016lx]\n",
      csr_read(scause), csr_read(sepc), csr_read(stval));
}
