#pragma once

#include <sbi/sbi_console.h>

#define DEBUG(msg, ...) \
  sbi_printf("[DEBUG] " msg " (%s:%d)\r\n", ## __VA_ARGS__, __FILE__, __LINE__);
