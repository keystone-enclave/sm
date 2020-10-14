#include <sbi/sbi_trap.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_tlb.h>
#include <sbi/sbi_ipi.h>
#include <sbi/sbi_string.h>
#include <sbi/riscv_locks.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_scratch.h>
#include <sbi/riscv_asm.h>
#include <sbi/sbi_ecall.h>
#include "sm_sbi_opensbi.h"
#include "pmp.h"
#include "sm-sbi.h"
#include "sm.h"

static int sbi_ecall_keystone_enclave_handler(unsigned long extid, unsigned long funcid,
                     struct sbi_trap_regs *regs,
                     unsigned long *args, unsigned long *out_val,
                     struct sbi_trap_info *out_trap)
{
  /* Note: regs is the sbi_trap.h format, which matches (... enough)
     the thread.h format, which means we can 'just use it' for now.
     This really needs to be handled far more cleanly. */
  // uintptr_t funcid = regs->a6; /* This was a7 in the old interface */
  // uintptr_t args[0] = regs->a0, args[1] = regs->a1, args[2] = regs->a2, args[3] = regs->a3;
  sbi_printf("Keystone extension handler, funcid = %lu\n",funcid);
  uintptr_t retval;
  switch(funcid){
  case SBI_SM_CREATE_ENCLAVE:
    retval = mcall_sm_create_enclave(args[0]);
    break;
  case SBI_SM_DESTROY_ENCLAVE:
    retval = mcall_sm_destroy_enclave(args[0]);
    break;
  case SBI_SM_RUN_ENCLAVE:
    retval = mcall_sm_run_enclave((uintptr_t*)regs, args[0]);
    break;
  case SBI_SM_EXIT_ENCLAVE:
    retval = mcall_sm_exit_enclave((uintptr_t*)regs, args[0]);
    break;
  case SBI_SM_STOP_ENCLAVE:
    retval = mcall_sm_stop_enclave((uintptr_t*)regs, args[0]);
    break;
  case SBI_SM_RESUME_ENCLAVE:
    retval = mcall_sm_resume_enclave((uintptr_t*)regs, args[0]);
    break;
  case SBI_SM_ATTEST_ENCLAVE:
    retval = mcall_sm_attest_enclave(args[0], args[1], args[2]);
    break;
  case SBI_SM_RANDOM:
    retval = mcall_sm_random();
    break;
  case SBI_SM_CALL_PLUGIN:
    retval = mcall_sm_call_plugin(args[0], args[1], args[2], args[3]);
    break;
  default:
    retval = ENCLAVE_NOT_IMPLEMENTED;
    break;

  }

  *out_val = retval;

  if(retval != ENCLAVE_SUCCESS){
    retval = SBI_ENOTSUPP;
  }
  else{
    retval = SBI_OK;
  }

  sbi_printf("Keystone extension returning %lu\n", retval);
  return retval;

}

// void sm_ipi_process(){
//   sbi_printf("ipi got %lx\r\n",csr_read(mhartid));
//   handle_pmp_ipi();
// }

static void sbi_ipi_process_pmp(struct sbi_scratch *scratch)
{
	handle_pmp_ipi();
}

static struct sbi_ipi_event_ops ipi_pmp = {
	.name = "IPI_PMP",
	.process = sbi_ipi_process_pmp,
};

static u32 PMP_IPI_EVENT;

void register_pmp_ipi()
{
  PMP_IPI_EVENT = sbi_ipi_event_create(&ipi_pmp);
}

int sm_sbi_send_ipi(uintptr_t recipient_mask){
  // struct sbi_scratch *scratch =  sbi_scratch_thishart_ptr();
  // struct sbi_trap_info uptrap;
  // uptrap.epc = 0;
  // uptrap.cause = 0;
  // uptrap.tval = 0;
  // struct sbi_tlb_info tlb_flush_info;
  // tlb_flush_info.start = 0;
  // tlb_flush_info.size = 0;
  // sbi_printf("senidng ipi %lx\r\n", recipient_mask);
  // return sbi_ipi_send_many(scratch, &uptrap, &recipient_mask,
  //                             SBI_SM_EVENT, &tlb_flush_info);
  return sbi_ipi_send_many(recipient_mask, 0, PMP_IPI_EVENT, NULL);
}



struct sbi_ecall_extension ecall_keystone_enclave = {
  .extid_start = SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
  .extid_end = SBI_EXT_EXPERIMENTAL_KEYSTONE_ENCLAVE,
  .handle = sbi_ecall_keystone_enclave_handler,
};
