#include <sbi/sbi_timer.h>
#include "time_fuzz.h"
#include "enclave.h"
#include "cpu.h"

void fuzzy_func() {
    enclave_id eid = cpu_get_enclave_id();
    struct enclave* enclave = get_enclave(eid);
    if (enclave->fuzzy_status == FUZZ_ENABLED) {
        // fuzz
    }
    
    // put this inside if statement later -- force pause
    // on everything for now for debugging
    const struct sbi_timer_device* device = sbi_timer_get_device();
    unsigned long long msPassed = (sbi_timer_value() / device->timer_freq) * 1000;
    // pause until next 10 ms block
    sbi_timer_mdelay(10 - (msPassed % 10));
}