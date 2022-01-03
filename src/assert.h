#ifndef __SM_ASSERT_H__

#include <sbi/sbi_console.h>
#include <sbi/sbi_hart.h>

#define sm_assert(cond) { \
  if (!(cond)) { \
    sbi_printf("[SM] assertion_failed at %s@%s:%d\r\n",__func__,__FILE__,__LINE__); \
    sbi_hart_hang(); \
  } \
}

#endif
