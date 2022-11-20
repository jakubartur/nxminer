/*
 * Copyright 2011-2013 Con Kolivas
 * Copyright 2011 Nils Schneider
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"
#ifdef HAVE_OPENCL

#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "findnonce.h"

struct pc_data
{
    struct thr_info* thr;
    struct work* work;
    uint8_t res[BUFFERSIZE];
    pthread_t pth;
    int found;
};

static void* postcalc_hash(void* userdata)
{
    struct pc_data* pcd = (struct pc_data*)userdata;
    struct thr_info* thr = pcd->thr;
    unsigned int entry = 0;

    pthread_detach(pthread_self());

    /* To prevent corrupt values in FOUND from trying to read beyond the
     * end of the res[] array */
    /*
    if (unlikely(pcd->res[FOUND] & ~FOUND))
    {
        applog(LOG_WARNING, "%s%d: invalid nonce count - HW error", thr->cgpu->drv->name, thr->cgpu->device_id);
        hw_errors++;
        thr->cgpu->hw_errors++;
        pcd->res[FOUND] &= FOUND;
    }
    */

    for (entry = 0; entry < pcd->res[FOUND]; entry++)
    {
        uint8_t nonce[16];
        memcpy(nonce, &pcd->res[1 + (entry*16)], 16);
        //char* strnonce = NULL;
        //applog(LOG_DEBUG, "OCL NONCE %u found in slot %d", nonce, entry);
        submit_nonce(thr, pcd->work, nonce);
    }
    discard_work(pcd->work);
    free(pcd);

    return NULL;
}

void postcalc_hash_async(struct thr_info* thr, struct work* work, uint8_t* res)
{
    struct pc_data* pcd = malloc(sizeof(struct pc_data));
    if (unlikely(!pcd))
    {
        applog(LOG_ERR, "Failed to malloc pc_data in postcalc_hash_async");
        return;
    }

    pcd->thr = thr;
    pcd->work = copy_work(work);
    memcpy(&pcd->res, res, BUFFERSIZE);

    if (pthread_create(&pcd->pth, NULL, postcalc_hash, (void*)pcd))
    {
        applog(LOG_ERR, "Failed to create postcalc_hash thread");
        return;
    }
}
#endif /* HAVE_OPENCL */
