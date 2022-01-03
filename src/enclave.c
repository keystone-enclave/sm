//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "enclave.h"
#include "mprv.h"
#include "pmp.h"
#include "page.h"
#include "cpu.h"
#include "debug.h"
#include "platform-hook.h"
#include "assert.h"
#include <sbi/sbi_string.h>
#include <sbi/riscv_asm.h>
#include <sbi/riscv_locks.h>
#include <sbi/sbi_console.h>

#define ENCL_MAX  16

struct enclave enclaves[ENCL_MAX];

#define ENCLAVE_EXISTS(eid) (eid >= 0 && eid < ENCL_MAX && enclaves[eid].state >= 0)

static spinlock_t encl_lock = SPIN_LOCK_INITIALIZER;

extern void save_host_regs(void);
extern void restore_host_regs(void);
extern byte dev_public_key[PUBLIC_KEY_SIZE];

/****************************
 *
 * Enclave utility functions
 * Internal use by SBI calls
 *
 ****************************/

void delegate_access_fault() {
  uintptr_t exceptions = csr_read(medeleg);
  exceptions |= (1U << CAUSE_STORE_ACCESS);
  exceptions |= (1U << CAUSE_FETCH_ACCESS);
  csr_write(medeleg, exceptions);
}
void undelegate_access_fault() {
  uintptr_t exceptions = csr_read(medeleg);
  exceptions &= ~(1U << CAUSE_STORE_ACCESS);
  exceptions &= ~(1U << CAUSE_FETCH_ACCESS);
  csr_write(medeleg, exceptions);
}

/* Internal function containing the core of the context switching
 * code to the enclave.
 *
 * Used by resume_enclave and run_enclave.
 *
 * Expects that eid has already been valided, and it is OK to run this enclave
*/
static inline void context_switch_to_enclave(struct sbi_trap_regs* regs,
                                                enclave_id eid,
                                                int load_parameters){
  /* save host context */
  swap_prev_state(&enclaves[eid].threads[0], regs, 1);
  swap_prev_mepc(&enclaves[eid].threads[0], regs, regs->mepc);
  swap_prev_mstatus(&enclaves[eid].threads[0], regs, regs->mstatus);

  uintptr_t interrupts = 0;
  csr_write(mideleg, interrupts);
  delegate_access_fault();

  if(load_parameters) {
    // passing parameters for a first run
    csr_write(sepc, (uintptr_t) enclaves[eid].params.user_entry);
    regs->mepc = (uintptr_t) enclaves[eid].params.runtime_entry - 4; // regs->mepc will be +4 before sbi_ecall_handler return
    regs->mstatus = (1 << MSTATUS_MPP_SHIFT);
    // $a1: (PA) DRAM base,
    regs->a1 = (uintptr_t) enclaves[eid].pa_params.dram_base;
    // $a2: (PA) DRAM size,
    regs->a2 = (uintptr_t) enclaves[eid].pa_params.dram_size;
    // $a3: (PA) kernel location,
    regs->a3 = (uintptr_t) enclaves[eid].pa_params.runtime_base;
    // $a4: (PA) user location,
    regs->a4 = (uintptr_t) enclaves[eid].pa_params.user_base;
    // $a5: (PA) freemem location,
    regs->a5 = (uintptr_t) enclaves[eid].pa_params.free_base;
    // $a6: (VA) utm base,
    regs->a6 = (uintptr_t) enclaves[eid].params.untrusted_ptr;
    // $a7: (size_t) utm size
    regs->a7 = (uintptr_t) enclaves[eid].params.untrusted_size;

    // switch to the initial enclave page table
    csr_write(satp, enclaves[eid].encl_satp);
  }

  switch_vector_enclave();

  // set PMP
  osm_pmp_set(PMP_NO_PERM);
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type != REGION_INVALID) {
      pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_ALL_PERM);
    }
  }
  /* additional allow for serverless TEE research */
  if (enclaves[eid].snapshot_eid != NO_PARENT)
  {
    enclave_id snapshot_eid = enclaves[eid].snapshot_eid;
    for (memid = 0; memid < ENCLAVE_REGIONS_MAX; memid++) {
      if (enclaves[snapshot_eid].regions[memid].type == REGION_SNAPSHOT) {
        pmp_set_keystone(enclaves[snapshot_eid].regions[memid].pmp_rid, PMP_READ_PERM);
      }
    }
  }

  // Setup any platform specific defenses
  platform_switch_to_enclave(&(enclaves[eid]));
  cpu_enter_enclave_context(eid);
}

static inline void context_switch_to_host(struct sbi_trap_regs *regs,
    enclave_id eid,
    int return_on_resume){

  // set PMP
  int memid;
  for(memid=0; memid < ENCLAVE_REGIONS_MAX; memid++) {
    if(enclaves[eid].regions[memid].type != REGION_INVALID) {
      pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_NO_PERM);
    }
  }
  /* additional allow for serverless TEE research */
  if (enclaves[eid].snapshot_eid != NO_PARENT)
  {
    enclave_id snapshot_eid = enclaves[eid].snapshot_eid;
    for (memid = 0; memid < ENCLAVE_REGIONS_MAX; memid++) {
      if (enclaves[snapshot_eid].regions[memid].type == REGION_SNAPSHOT) {
        pmp_set_keystone(enclaves[snapshot_eid].regions[memid].pmp_rid, PMP_NO_PERM);
      }
    }
  }

  osm_pmp_set(PMP_ALL_PERM);

  uintptr_t interrupts = MIP_SSIP | MIP_STIP | MIP_SEIP;
  csr_write(mideleg, interrupts);
  undelegate_access_fault();

  /* restore host context */
  swap_prev_state(&enclaves[eid].threads[0], regs, return_on_resume);
  swap_prev_mepc(&enclaves[eid].threads[0], regs, regs->mepc);
  swap_prev_mstatus(&enclaves[eid].threads[0], regs, regs->mstatus);

  switch_vector_host();

  uintptr_t pending = csr_read(mip);

  if (pending & MIP_MTIP) {
    csr_clear(mip, MIP_MTIP);
    csr_set(mip, MIP_STIP);
  }
  if (pending & MIP_MSIP) {
    csr_clear(mip, MIP_MSIP);
    csr_set(mip, MIP_SSIP);
  }
  if (pending & MIP_MEIP) {
    csr_clear(mip, MIP_MEIP);
    csr_set(mip, MIP_SEIP);
  }

  // Reconfigure platform specific defenses
  platform_switch_from_enclave(&(enclaves[eid]));

  cpu_exit_enclave_context();

  return;
}


// TODO: This function is externally used.
// refactoring needed
/*
 * Init all metadata as needed for keeping track of enclaves
 * Called once by the SM on startup
 */
void enclave_init_metadata(){
  enclave_id eid;
  int i=0;

  /* Assumes eids are incrementing values, which they are for now */
  for(eid=0; eid < ENCL_MAX; eid++){
    enclaves[eid].state = INVALID;

    // Clear out regions
    for(i=0; i < ENCLAVE_REGIONS_MAX; i++){
      enclaves[eid].regions[i].type = REGION_INVALID;
    }
    /* Fire all platform specific init for each enclave */
    platform_init_enclave(&(enclaves[eid]));
  }

}

static unsigned long clean_enclave_memory(uintptr_t utbase, uintptr_t utsize)
{

  // This function is quite temporary. See issue #38

  // Zero out the untrusted memory region, since it may be in
  // indeterminate state.
  sbi_memset((void*)utbase, 0, utsize);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static unsigned long encl_alloc_eid(enclave_id* _eid)
{
  enclave_id eid;

  spin_lock(&encl_lock);

  for(eid=0; eid<ENCL_MAX; eid++)
  {
    if(enclaves[eid].state == INVALID){
      break;
    }
  }
  if(eid != ENCL_MAX)
    enclaves[eid].state = ALLOCATED;

  spin_unlock(&encl_lock);

  if(eid != ENCL_MAX){
    *_eid = eid;
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
  }
  else{
    return SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  }
}

static unsigned long encl_free_eid(enclave_id eid)
{
  spin_lock(&encl_lock);
  enclaves[eid].state = INVALID;
  spin_unlock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

int get_enclave_region_index(enclave_id eid, enum enclave_region_type type){
  size_t i;
  for(i = 0;i < ENCLAVE_REGIONS_MAX; i++){
    if(enclaves[eid].regions[i].type == type){
      return i;
    }
  }
  // No such region for this enclave
  return -1;
}

uintptr_t get_enclave_region_size(enclave_id eid, int memid)
{
  if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
    return pmp_region_get_size(enclaves[eid].regions[memid].pmp_rid);

  return 0;
}

uintptr_t get_enclave_region_base(enclave_id eid, int memid)
{
  if (0 <= memid && memid < ENCLAVE_REGIONS_MAX)
    return pmp_region_get_addr(enclaves[eid].regions[memid].pmp_rid);

  return 0;
}

// TODO: This function is externally used by sm-sbi.c.
// Change it to be internal (remove from the enclave.h and make static)
/* Internal function enforcing a copy source is from the untrusted world.
 * Does NOT do verification of dest, assumes caller knows what that is.
 * Dest should be inside the SM memory.
 */
unsigned long copy_enclave_create_args(uintptr_t src, struct keystone_sbi_create* dest){

  int region_overlap = copy_to_sm(dest, src, sizeof(struct keystone_sbi_create));

  if (region_overlap)
    return SBI_ERR_SM_ENCLAVE_REGION_OVERLAPS;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long copy_enclave_clone_args(uintptr_t src, struct keystone_sbi_clone_create *dest){

  int region_overlap = copy_to_sm(dest, src, sizeof(struct keystone_sbi_clone_create));

  if (region_overlap)
    return SBI_ERR_SM_ENCLAVE_REGION_OVERLAPS;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/* copies data from enclave, source must be inside EPM */
static unsigned long copy_enclave_data(struct enclave* enclave,
                                          void* dest, uintptr_t source, size_t size) {

  int illegal = copy_to_sm(dest, source, size);

  if(illegal)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

/* copies data into enclave, destination must be inside EPM */
static unsigned long copy_enclave_report(struct enclave* enclave,
                                            uintptr_t dest, struct report* source) {

  int illegal = copy_from_sm(dest, source, sizeof(struct report));

  if(illegal)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
  else
    return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

static int is_create_args_valid(struct keystone_sbi_create* args)
{
  uintptr_t epm_start, epm_end;

  /* printm("[create args info]: \r\n\tepm_addr: %llx\r\n\tepmsize: %llx\r\n\tutm_addr: %llx\r\n\tutmsize: %llx\r\n\truntime_addr: %llx\r\n\tuser_addr: %llx\r\n\tfree_addr: %llx\r\n", */
  /*        args->epm_region.paddr, */
  /*        args->epm_region.size, */
  /*        args->utm_region.paddr, */
  /*        args->utm_region.size, */
  /*        args->runtime_paddr, */
  /*        args->user_paddr, */
  /*        args->free_paddr); */

  // check if physical addresses are valid
  if (args->epm_region.size <= 0)
    return 0;

  // check if overflow
  if (args->epm_region.paddr >=
      args->epm_region.paddr + args->epm_region.size)
    return 0;
  if (args->utm_region.paddr >=
      args->utm_region.paddr + args->utm_region.size)
    return 0;

  epm_start = args->epm_region.paddr;
  epm_end = args->epm_region.paddr + args->epm_region.size;

  // check if physical addresses are in the range
  if (args->runtime_paddr < epm_start ||
      args->runtime_paddr >= epm_end)
    return 0;
  if (args->user_paddr < epm_start ||
      args->user_paddr >= epm_end)
    return 0;
  if (args->free_paddr < epm_start ||
      args->free_paddr > epm_end)
      // note: free_paddr == epm_end if there's no free memory
    return 0;

  // check the order of physical addresses
  if (args->runtime_paddr > args->user_paddr)
    return 0;
  if (args->user_paddr > args->free_paddr)
    return 0;

  return 1;
}

/*********************************
 *
 * Enclave SBI functions
 * These are exposed to S-mode via the sm-sbi interface
 *
 *********************************/


/* This handles creation of a new enclave, based on arguments provided
 * by the untrusted host.
 *
 * This may fail if: it cannot allocate PMP regions, EIDs, etc
 */
unsigned long create_enclave(unsigned long *eidptr, struct keystone_sbi_create create_args)
{
  /* EPM and UTM parameters */
  uintptr_t base = create_args.epm_region.paddr;
  size_t size = create_args.epm_region.size;
  uintptr_t utbase = create_args.utm_region.paddr;
  size_t utsize = create_args.utm_region.size;

  enclave_id eid;
  unsigned long ret;
  int region, shared_region;

  /* Runtime parameters */
  if(!is_create_args_valid(&create_args))
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  /* set va params */
  struct runtime_va_params_t params = create_args.params;
  struct runtime_pa_params pa_params;
  pa_params.dram_base = base;
  pa_params.dram_size = size;
  pa_params.runtime_base = create_args.runtime_paddr;
  pa_params.user_base = create_args.user_paddr;
  pa_params.free_base = create_args.free_paddr;


  // allocate eid
  ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  if (encl_alloc_eid(&eid) != SBI_ERR_SM_ENCLAVE_SUCCESS)
    goto error;

  // create a PMP region bound to the enclave
  ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
  if(pmp_region_init_atomic(base, size, PMP_PRI_ANY, &region, 0))
    goto free_encl_idx;

  // create PMP region for shared memory
  if(pmp_region_init_atomic(utbase, utsize, PMP_PRI_BOTTOM, &shared_region, 0))
    goto free_region;

  // set pmp registers for private region (not shared)
  if(pmp_set_global(region, PMP_NO_PERM))
    goto free_shared_region;

  // cleanup some memory regions for sanity See issue #38
  clean_enclave_memory(utbase, utsize);


  // initialize enclave metadata
  enclaves[eid].eid = eid;
  enclaves[eid].snapshot_eid = NO_PARENT;
  enclaves[eid].ref_count = 0;
  enclaves[eid].regions[0].pmp_rid = region;
  enclaves[eid].regions[0].type = REGION_EPM;
  enclaves[eid].regions[1].pmp_rid = shared_region;
  enclaves[eid].regions[1].type = REGION_UTM;
#if __riscv_xlen == 32
  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV32 << HGATP_MODE_SHIFT));
#else
  enclaves[eid].encl_satp = ((base >> RISCV_PGSHIFT) | (SATP_MODE_SV39 << HGATP_MODE_SHIFT));
#endif
  enclaves[eid].n_thread = 0;
  enclaves[eid].params = params;
  enclaves[eid].pa_params = pa_params;

  //Enclave created without clone have no free list
  enclaves[eid].free_list = -1;

  /* Init enclave state (regs etc) */
  clean_state(&enclaves[eid].threads[0]);

  /* Platform create happens as the last thing before hashing/etc since
     it may modify the enclave struct */
  ret = platform_create_enclave(&enclaves[eid]);
  if (ret)
    goto unset_region;

  /* Validate memory, prepare hash and signature for attestation */
  spin_lock(&encl_lock); // FIXME This should error for second enter.
  ret = validate_and_hash_enclave(&enclaves[eid]);
  /* The enclave is fresh if it has been validated and hashed but not run yet. */
  if (ret)
    goto unlock;

  enclaves[eid].state = FRESH;
  /* EIDs are unsigned int in size, copy via simple copy */
  *eidptr = eid;

  spin_unlock(&encl_lock);
  return SBI_ERR_SM_ENCLAVE_SUCCESS;

unlock:
  spin_unlock(&encl_lock);
// free_platform:
  platform_destroy_enclave(&enclaves[eid]);
unset_region:
  pmp_unset_global(region);
free_shared_region:
  pmp_region_free_atomic(shared_region);
free_region:
  pmp_region_free_atomic(region);
free_encl_idx:
  encl_free_eid(eid);
error:
  return ret;
}

/*
 * Fully destroys an enclave
 * Deallocates EID, clears epm, etc
 * Fails only if the enclave isn't running.
 */
unsigned long destroy_enclave(enclave_id eid)
{
  int destroyable;

  spin_lock(&encl_lock);
  destroyable = (ENCLAVE_EXISTS(eid)
                 && enclaves[eid].state <= STOPPED
                 && enclaves[eid].ref_count == 0);
  /* update the enclave state first so that
   * no SM can run the enclave any longer */
  if(destroyable)
    enclaves[eid].state = DESTROYING;
  spin_unlock(&encl_lock);

  if(!destroyable)
    return SBI_ERR_SM_ENCLAVE_NOT_DESTROYABLE;


  // 0. Let the platform specifics do cleanup/modifications
  platform_destroy_enclave(&enclaves[eid]);

  //If enclave derived from snapshot, decrement ref_count
  spin_lock(&encl_lock);
  if (enclaves[eid].snapshot_eid != NO_PARENT)
  {
    enclave_id snapshot_eid = enclaves[eid].snapshot_eid;
    enclaves[snapshot_eid].ref_count--;
  }
  spin_unlock(&encl_lock);


  // 1. clear all the data in the enclave pages
  // requires no lock (single runner)
  int i;
  void* base;
  size_t size;
  region_id rid;
  for(i = 0; i < ENCLAVE_REGIONS_MAX; i++){
    if(enclaves[eid].regions[i].type == REGION_INVALID ||
       enclaves[eid].regions[i].type == REGION_UTM)
      continue;
    //1.a Clear all pages
    rid = enclaves[eid].regions[i].pmp_rid;
    base = (void*) pmp_region_get_addr(rid);
    size = (size_t) pmp_region_get_size(rid);
    sbi_memset((void*) base, 0, size);

    //1.b free pmp region
    pmp_unset_global(rid);
    pmp_region_free_atomic(rid);
  }

  // 2. free pmp region for UTM
  rid = get_enclave_region_index(eid, REGION_UTM);
  if(rid != -1)
    pmp_region_free_atomic(enclaves[eid].regions[rid].pmp_rid);

  for(i=0; i < ENCLAVE_REGIONS_MAX; i++){
    enclaves[eid].regions[i].type = REGION_INVALID;
  }

  // clean metadata
  sbi_memset((void*) &enclaves[eid], 0, sizeof(struct enclave));
  // 3. release eid
  encl_free_eid(eid);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}


unsigned long run_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int runable;

  spin_lock(&encl_lock);
  runable = (ENCLAVE_EXISTS(eid)
            && enclaves[eid].state == FRESH);
  if(runable) {
    enclaves[eid].state = RUNNING;
    enclaves[eid].n_thread++;
  }
  spin_unlock(&encl_lock);

  if(!runable) {
    return SBI_ERR_SM_ENCLAVE_NOT_FRESH;
  }

  // Enclave is OK to run, context switch to it
  context_switch_to_enclave(regs, eid, 1);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long exit_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int exitable;

  spin_lock(&encl_lock);
  exitable = enclaves[eid].state == RUNNING;
  if (exitable) {
    enclaves[eid].n_thread--;
    if(enclaves[eid].n_thread == 0)
      enclaves[eid].state = STOPPED;
  }
  spin_unlock(&encl_lock);

  if(!exitable)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

  context_switch_to_host(regs, eid, 0);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long stop_enclave(struct sbi_trap_regs *regs, uint64_t request, enclave_id eid)
{
  int stoppable;

  spin_lock(&encl_lock);
  stoppable = enclaves[eid].state == RUNNING;
  if (stoppable) {
    enclaves[eid].n_thread--;
    if(enclaves[eid].n_thread == 0)
      enclaves[eid].state = STOPPED;
  }
  spin_unlock(&encl_lock);

  if(!stoppable)
    return SBI_ERR_SM_ENCLAVE_NOT_RUNNING;

  context_switch_to_host(regs, eid, request == STOP_EDGE_CALL_HOST);

  switch(request) {
    case(STOP_TIMER_INTERRUPT):
      return SBI_ERR_SM_ENCLAVE_INTERRUPTED;
    case(STOP_EDGE_CALL_HOST):
      return SBI_ERR_SM_ENCLAVE_EDGE_CALL_HOST;
    case(STOP_CLONE):
      return SBI_ERR_SM_ENCLAVE_CLONE;
    default:
      return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;
  }
}

unsigned long resume_enclave(struct sbi_trap_regs *regs, enclave_id eid)
{
  int resumable;

  spin_lock(&encl_lock);
  resumable = (ENCLAVE_EXISTS(eid)
               && (enclaves[eid].state == RUNNING || enclaves[eid].state == STOPPED)
               && enclaves[eid].n_thread < MAX_ENCL_THREADS);

  if(!resumable) {
    spin_unlock(&encl_lock);
    return SBI_ERR_SM_ENCLAVE_NOT_RESUMABLE;
  } else {
    enclaves[eid].n_thread++;
    enclaves[eid].state = RUNNING;
  }
  spin_unlock(&encl_lock);

  // Enclave is OK to resume, context switch to it
  context_switch_to_enclave(regs, eid, 0);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

unsigned long attest_enclave(uintptr_t report_ptr, uintptr_t data, uintptr_t size, enclave_id eid)
{
  int attestable;
  struct report report;
  int ret;

  if (size > ATTEST_DATA_MAXLEN)
    return SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;

  spin_lock(&encl_lock);
  attestable = (ENCLAVE_EXISTS(eid)
                && (enclaves[eid].state >= FRESH));

  if(!attestable) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_INITIALIZED;
    goto err_unlock;
  }

  /* copy data to be signed */
  ret = copy_enclave_data(&enclaves[eid], report.enclave.data,
      data, size);
  report.enclave.data_len = size;

  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_NOT_ACCESSIBLE;
    goto err_unlock;
  }

  spin_unlock(&encl_lock); // Don't need to wait while signing, which might take some time

  sbi_memcpy(report.dev_public_key, dev_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(report.sm.hash, sm_hash, MDSIZE);
  sbi_memcpy(report.sm.public_key, sm_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(report.sm.signature, sm_signature, SIGNATURE_SIZE);
  sbi_memcpy(report.enclave.hash, enclaves[eid].hash, MDSIZE);
  sm_sign(report.enclave.signature,
      &report.enclave,
      sizeof(struct enclave_report)
      - SIGNATURE_SIZE
      - ATTEST_DATA_MAXLEN + size);

  spin_lock(&encl_lock);

  /* copy report to the enclave */
  ret = copy_enclave_report(&enclaves[eid],
      report_ptr,
      &report);

  if (ret) {
    ret = SBI_ERR_SM_ENCLAVE_ILLEGAL_ARGUMENT;
    goto err_unlock;
  }

  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

err_unlock:
  spin_unlock(&encl_lock);
  return ret;
}

unsigned long get_sealing_key(uintptr_t sealing_key, uintptr_t key_ident,
                                 size_t key_ident_size, enclave_id eid)
{
  struct sealing_key *key_struct = (struct sealing_key *)sealing_key;
  int ret;

  /* derive key */
  ret = sm_derive_sealing_key((unsigned char *)key_struct->key,
                              (const unsigned char *)key_ident, key_ident_size,
                              (const unsigned char *)enclaves[eid].hash);
  if (ret)
    return SBI_ERR_SM_ENCLAVE_UNKNOWN_ERROR;

  /* sign derived key */
  sm_sign((void *)key_struct->signature, (void *)key_struct->key,
          SEALING_KEY_SIZE);

  return SBI_ERR_SM_ENCLAVE_SUCCESS;
}

typedef uintptr_t pte_t;

static int traverse_pgtable_and_relocate_pages(int level, pte_t* tb, uintptr_t vaddr,
   uintptr_t offset, uintptr_t src_base, size_t src_size, uintptr_t dst_base, size_t dst_size)
{
  pte_t* walk;
  int ret = 0;
  int i=0;

  for (walk=tb, i=0; walk < tb + (RISCV_PGSIZE/sizeof(pte_t)) ; walk += 1, i++)
  {
    if(*walk == 0)
      continue;

    pte_t pte = *walk;
    uintptr_t phys_addr = (pte >> PTE_PPN_SHIFT) << RISCV_PGSHIFT;

    if (phys_addr >= src_base && phys_addr < (src_base + src_size))
    {
      *walk = (pte & 0x3ff) | (((phys_addr + offset) >> RISCV_PGSHIFT) << PTE_PPN_SHIFT);
			sm_assert(dst_base <= (uintptr_t) walk && (uintptr_t) walk < (dst_base + dst_size));
      if (level == 1) {
        //DEBUG("SM is relocating %lx to %lx (VA: %lx) (pte: %lx)",
        //    phys_addr, phys_addr + offset, ((vaddr << 9) | (i&0x1ff))<<12, pte);
      }
      else {
        //DEBUG("SM is relocating %lx to %lx (pte: %lx)", phys_addr, phys_addr + offset, pte);
      }
    }

    if(level > 1 && !(pte &(PTE_X|PTE_R|PTE_W)))
    {
      if(level == 3 && (i&0x100))
        vaddr = 0xffffffffffffffffUL;
      ret |= traverse_pgtable_and_relocate_pages(level - 1, (pte_t*) (phys_addr + offset), (vaddr << 9) | (i&0x1ff),
          offset, src_base, src_size, dst_base, dst_size);
    }
  }
  return ret;
}

// traverse parent_satp, copy anything that is in src to dst and update page table
// return new satp
uintptr_t copy_and_remap(uintptr_t parent_satp,
    uintptr_t src_base, size_t src_size,
    uintptr_t dst_base, size_t dst_size)
{
  uintptr_t ret;
  uintptr_t offset = dst_base - src_base;

  DEBUG("copy_and_remap (%lx, %lx, %ld, %lx, %ld)", parent_satp, src_base, src_size, dst_base, dst_size);
  // relocate root page table
  uintptr_t parent_root_page_table = parent_satp << RISCV_PGSHIFT;
  uintptr_t root_page_table = parent_root_page_table + offset;

  sm_assert (src_size == dst_size);
  sbi_memcpy((void*) dst_base, (void*) src_base, src_size);

  ret = ((root_page_table >> RISCV_PGSHIFT) | (SATP_MODE_SV39 << HGATP_MODE_SHIFT));

  sm_assert (!traverse_pgtable_and_relocate_pages(3, (pte_t*) root_page_table, 0,
      offset, src_base, src_size, dst_base, dst_size));

  return ret;
}

unsigned long clone_enclave(unsigned long *eidptr, struct keystone_sbi_clone_create create_args){

  enclave_id parent_eid = create_args.snapshot_eid;
  enclave_id snapshot_eid;
  enclave_id eid = -1;
  int region, shared_region;
  bool is_parent_snapshot = false;

  /* Check if eid */
  if(!(ENCLAVE_EXISTS(parent_eid))) {
    return SBI_ERR_SM_ENCLAVE_INVALID_ID;
  }

  // case 1: if parent enclave is snapshot
  if(enclaves[parent_eid].state == SNAPSHOT) {
    snapshot_eid = parent_eid;
    is_parent_snapshot = true;
  }
  // case 2: if parent enclave is not a snapshot
  else {
    // case 2 - i: if parent enclave has snapshot
    if (enclaves[parent_eid].snapshot_eid != NO_PARENT)
    {
      snapshot_eid = enclaves[parent_eid].snapshot_eid;
      is_parent_snapshot = false;
    }
    // case 2 - ii: if parent enclave doesn't have snapshot
    else
    {
      snapshot_eid = NO_PARENT;
      is_parent_snapshot = false;
    }
  }

  DEBUG("clone : parent (%d), snapshot (%d), is_parent_snapshot (%d)", parent_eid, snapshot_eid, is_parent_snapshot);

  if (snapshot_eid != NO_PARENT) {
    sm_assert(ENCLAVE_EXISTS(snapshot_eid));

    // todo thread-unsafe
    enclaves[snapshot_eid].ref_count ++;
  }

  /* EPM and UTM parameters */
  uintptr_t base = create_args.epm_region.paddr;
  size_t size = create_args.epm_region.size;
  uintptr_t utbase = create_args.utm_region.paddr;
  size_t utsize = create_args.utm_region.size;
  uintptr_t retval = create_args.retval;

  // allocate eid
  unsigned long ret = SBI_ERR_SM_ENCLAVE_NO_FREE_RESOURCE;
  if (encl_alloc_eid(&eid) != SBI_ERR_SM_ENCLAVE_SUCCESS)
    goto error;

  // create a PMP region bound to the enclave
  ret = SBI_ERR_SM_ENCLAVE_PMP_FAILURE;
  if(pmp_region_init_atomic(base, size, PMP_PRI_ANY, &region, 0))
    goto free_encl_idx;

  // create PMP region for shared memory
  if(pmp_region_init_atomic(utbase, utsize, PMP_PRI_BOTTOM, &shared_region, 0))
    goto free_region;

  // set pmp registers for private region (not shared)
  if(pmp_set_global(region, PMP_NO_PERM))
    goto free_shared_region;

  ret = SBI_ERR_SM_ENCLAVE_SUCCESS;

  // cleanup some memory regions for sanity See issue #38
  clean_enclave_memory(utbase, utsize);

  // initialize enclave's unique metadata
  enclaves[eid].eid = eid;
  enclaves[eid].snapshot_eid = snapshot_eid;

  //Initialize enclave free list
  enclaves[eid].free_list = base;

  enclaves[eid].regions[0].pmp_rid = region;
  enclaves[eid].regions[0].type = REGION_EPM;
  enclaves[eid].regions[1].pmp_rid = shared_region;
  enclaves[eid].regions[1].type = REGION_UTM;

  //Copy parameters from snapshot to enclave
  if (is_parent_snapshot) {
    enclaves[eid].encl_satp = enclaves[parent_eid].encl_satp;
  }
  else {
    enclaves[eid].encl_satp =
      copy_and_remap(enclaves[parent_eid].encl_satp,
          enclaves[parent_eid].pa_params.dram_base, enclaves[parent_eid].pa_params.dram_size,
          base, size);
  }
  // Copy the page table (they should both be the same page)
  // sbi_memcpy((void *) base, (void *) enclaves[snapshot_eid].pa_params.dram_base, PAGE_SIZE);
  enclaves[eid].n_thread = 0;

  sbi_memcpy(&enclaves[eid].threads[0], &enclaves[parent_eid].threads[0], sizeof(struct thread_state));
  //sbi_memcpy(&enclaves[eid].params, &enclaves[parent_eid].params, sizeof(struct runtime_va_params_t ));
  //sbi_memcpy(&enclaves[eid].pa_params, &enclaves[parent_eid].pa_params, sizeof(struct runtime_pa_params));

  enclaves[eid].pa_params.dram_base = base;
  enclaves[eid].pa_params.dram_size = size;
  enclaves[eid].threads[0].prev_csrs.satp = enclaves[eid].encl_satp;
  enclaves[eid].threads[0].prev_state.a0 = base;
  enclaves[eid].threads[0].prev_state.a1 = size;
  enclaves[eid].threads[0].prev_state.a2 = utbase;
  enclaves[eid].threads[0].prev_state.a3 = utsize;
  enclaves[eid].threads[0].prev_state.a4 = base;
  enclaves[eid].threads[0].prev_state.a5 = retval;

  DEBUG("base: %lx, size: %lx, utbase: %lx, utsize: %lx, retval: %lx", base, size, utbase, utsize, retval);

  //Copy arguments prepared by snapshot
  //struct sbi_snapshot_ret *snapshot_ret = (struct sbi_snapshot_ret *) enclaves[eid].threads->prev_state.a0;
  //struct sbi_snapshot_ret args = {utbase, utsize, base, size};
  //sbi_memcpy(snapshot_ret, &args, sizeof(struct sbi_snapshot_ret));

  enclaves[eid].state = RUNNING;
  *eidptr = eid;
  goto error;


free_shared_region:
  pmp_region_free_atomic(shared_region);
free_region:
  pmp_region_free_atomic(region);
free_encl_idx:
  encl_free_eid(eid);
error:
  return ret;
}

unsigned long create_snapshot(struct sbi_trap_regs *regs, enclave_id eid, uintptr_t boot_pc)
{
  sm_assert(enclaves[eid].state != SNAPSHOT);
  int stoppable;

  spin_lock(&encl_lock);
  stoppable = enclaves[eid].state == RUNNING;
  if (stoppable) {
    enclaves[eid].n_thread--;
    if(enclaves[eid].n_thread == 0)
      enclaves[eid].state = STOPPED;
  }
  spin_unlock(&encl_lock);

  // we are not going to remap
  if (enclaves[eid].snapshot_eid == NO_PARENT)
  {
    enclaves[eid].state = SNAPSHOT;
    enclaves[eid].encl_satp = 0;
    regs->mepc = boot_pc;
  }
  else
  {
    // we are not going to remap;
    regs->a0 = 0;
    enclaves[eid].encl_satp = csr_read(satp);
    context_switch_to_host(regs, eid, 0);
    return SBI_ERR_SM_ENCLAVE_SNAPSHOT;
  }

  /*
    * Set current enclave's PMP regions to SNAPSHOT
    * Copy any EPM regions to the snapshot (we don't care about UTM)
    * Upon context switch to enclave, PMP will be set to READ-ONLY
  */
  for(int memid = 0; memid < ENCLAVE_REGIONS_MAX; memid++) {

    /* Switch off PMP registers*/
    if(enclaves[eid].regions[memid].type != REGION_INVALID){
      pmp_set_keystone(enclaves[eid].regions[memid].pmp_rid, PMP_NO_PERM);
    }

    /* Copy EPM PMP to snapshot and mark it as read-only */
    if(enclaves[eid].regions[memid].type == REGION_EPM){
      enclaves[eid].regions[memid].type = REGION_SNAPSHOT;
    }

    if(enclaves[eid].regions[memid].type == REGION_UTM){
      pmp_region_free_atomic(enclaves[eid].regions[memid].pmp_rid);
      enclaves[eid].regions[memid].type = REGION_INVALID;
    }
  }

  context_switch_to_host(regs, eid, 0);

  return SBI_ERR_SM_ENCLAVE_SNAPSHOT;
}
