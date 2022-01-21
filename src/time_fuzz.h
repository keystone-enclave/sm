#ifndef _TIME_FUZZ_H_
#define _TIME_FUZZ_H_

void fuzzy_func();

// copied from keystone-runtime/timex.h
typedef unsigned long cycles_t;

static inline cycles_t get_cycles_inline(void)
{
	cycles_t n;

	__asm__ __volatile__ (
		"rdtime %0"
		: "=r" (n));
	return n;
}
#define get_cycles get_cycles_inline

// chungmcl: changed uint64_t to unsigned long long int because compiler said uint64_t was undefined
static inline unsigned long long int get_cycles64(void)
{
        return get_cycles();
}

#define ARCH_HAS_READ_CURRENT_TIMER

static inline int read_current_timer(unsigned long *timer_val)
{
	*timer_val = get_cycles();
	return 0;
}
// copied from keystone-runtime/timex.h

#endif