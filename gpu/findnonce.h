#ifndef __FINDNONCE_H__
#define __FINDNONCE_H__
#include "config.h"
#include "miner.h"

#define MAX_WORK_SIZE 256

#define MAXTHREADS (0xFFFFFFFEULL)

#define BUFFERSIZE (1 + (16 * MAX_WORK_SIZE))
// found is index 0
#define FOUND (0x00)

#ifdef HAVE_OPENCL
extern void postcalc_hash_async(struct thr_info* thr, struct work* work, uint8_t* res);
#endif /* HAVE_OPENCL */
#endif /*__FINDNONCE_H__*/
