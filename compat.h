#ifndef __COMPAT_H__
#define __COMPAT_H__

#ifdef WIN32
#include <errno.h>
#include <pthread.h>
#include <sys/time.h>
#include <time.h>

#include <windows.h>

#include "miner.h" // for timersub

#ifndef WINPTHREAD_API
// win thread api has its own nanosleep
static inline int nanosleep(const struct timespec* req, struct timespec* rem)
{
    struct timeval tstart;
    DWORD msecs;

    gettimeofday(&tstart, NULL);
    msecs = (req->tv_sec * 1000) + ((999999 + req->tv_nsec) / 1000000);

    if (SleepEx(msecs, true) == WAIT_IO_COMPLETION)
    {
        if (rem)
        {
            struct timeval tdone, tnow, tleft;
            tdone.tv_sec = tstart.tv_sec + req->tv_sec;
            tdone.tv_usec = tstart.tv_usec + ((999 + req->tv_nsec) / 1000);
            if (tdone.tv_usec > 1000000)
            {
                tdone.tv_usec -= 1000000;
                ++tdone.tv_sec;
            }

            gettimeofday(&tnow, NULL);
            if (timercmp(&tnow, &tdone, >))
                return 0;
            timersub(&tdone, &tnow, &tleft);

            rem->tv_sec = tleft.tv_sec;
            rem->tv_nsec = tleft.tv_usec * 1000;
        }
        errno = EINTR;
        return -1;
    }
    return 0;
}
#endif

// _UNISTD_H will define sleep, if it is missing define it ourselves
#ifndef _UNISTD_H
static inline int sleep(unsigned int secs)
{
    struct timespec req, rem;
    req.tv_sec = secs;
    req.tv_nsec = 0;
    if (!nanosleep(&req, &rem))
        return 0;
    return rem.tv_sec + (rem.tv_nsec ? 1 : 0);
}

#endif

enum
{
    PRIO_PROCESS = 0,
};

static inline int setpriority(__maybe_unused int which, __maybe_unused int who, __maybe_unused int prio)
{
    /* FIXME - actually do something */
    return 0;
}

typedef unsigned long int ulong;
typedef unsigned short int ushort;
typedef unsigned int uint;

#ifndef __SUSECONDS_T_TYPE
typedef long suseconds_t;
#endif

#ifndef WIN_PTHREADS_H
#define PTH(thr) ((thr)->pth.p)
#else
#define PTH(thr) ((thr)->pth)
#endif
#else
#define PTH(thr) ((thr)->pth)
#endif /* WIN32 */

#endif /* __COMPAT_H__ */
