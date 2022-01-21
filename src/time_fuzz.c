#include "time_fuzz.h"
#include "enclave.h"
#include "cpu.h"

// for debugging -- makes the SM pause for a "noticeable" amount of time
// on my machine: i9-9880H 32GB RAM running this all on QEMU
#define ARBITRARY_PAUSE 10000000

void fuzzy_func() {
    //enclave_id eid = cpu_get_enclave_id();
    //struct enclave* enclave = get_enclave(eid);
    //if (enclave->fuzzy_status == FUZZ_ENABLED) {
    //    // fuzz
    //}

    cycles_t start_time;
    read_current_timer(&start_time);

    cycles_t t = start_time;
    while (t < (start_time + ARBITRARY_PAUSE)) {
        read_current_timer(&t);
    }
}