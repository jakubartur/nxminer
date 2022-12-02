/*
 * Copyright 2011-2013 Con Kolivas
 * Copyright 2011-2012 Luke Dashjr
 * Copyright 2010 Jeff Garzik
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#ifdef HAVE_CURSES
#include <ncurses/curses.h>
#endif

#include <assert.h>
#include <math.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#ifndef WIN32
#include <sys/resource.h>
#endif

#include <ccan/opt/opt.h>
#include <curl/curl.h>
#include <jansson.h>
#include <libgen.h>
#include <sha2.h>

#include "gpu/adl.h"
#include "bench_block.h"
#include "compat.h"
#include "gpu/driver-opencl.h"
#include "gpu/findnonce.h"
#include "miner.h"

#include <openssl/rand.h>

#if defined(unix)
#include <errno.h>
#include <fcntl.h>
#include <sys/wait.h>
#endif

struct strategies strategies[] = {
    {"Failover"},
    {"Round Robin"},
    {"Rotate"},
    {"Load Balance"},
    {"Balance"},
};

static char packagename[100];

bool opt_protocol;
static bool opt_benchmark;
bool want_per_device_stats;
bool use_syslog;
bool opt_quiet;
bool opt_realquiet;
bool opt_loginput;
bool opt_compact;
const int opt_cutofftemp = 95;
int32_t opt_log_interval = 5;
int32_t opt_queue = 1;
int32_t opt_scantime = 120;
int32_t opt_expiry = 240;
int32_t opt_bench_algo = -1;
uint64_t global_hashrate;

#if defined(HAVE_OPENCL)
int nDevs;
#endif

#ifdef HAVE_OPENCL
int opt_dynamic_interval = 7;
int opt_g_threads = -1;
int gpu_threads;
#endif

bool opt_restart = true;
static bool opt_nogpu;

struct list_head scan_devices;
static signed int devices_enabled;
static bool opt_removedisabled;
int total_devices;
struct cgpu_info** devices;
bool have_opencl;
int opt_n_threads = -1;
int mining_threads;
int num_processors;

#ifdef HAVE_CURSES
bool use_curses = true;
#else
bool use_curses;
#endif

static bool opt_submit_stale = true;
static int opt_shares;
bool opt_fail_only;
bool opt_autofan;
bool opt_autoengine;
bool opt_noadl;
char* opt_api_allow = NULL;
char* opt_api_groups;
char* opt_api_description = PACKAGE_STRING;
int32_t opt_api_port = 4028;
bool opt_api_listen;
bool opt_api_network;
bool opt_delaynet;
bool opt_disable_pool;
bool opt_worktime;

char* opt_kernel_path;
char* cgminer_path;

#define QUIET (opt_quiet || opt_realquiet)

struct thr_info* control_thr;
struct thr_info** mining_thr;
static int gwsched_thr_id;
static int stage_thr_id;
static int watchpool_thr_id;
static int watchdog_thr_id;
#ifdef HAVE_CURSES
static int input_thr_id;
#endif
int gpur_thr_id;
static int api_thr_id;
static int total_control_threads;
bool hotplug_mode;
static int new_devices;
static int new_threads;
static int start_devices;

pthread_mutex_t hash_lock;
static pthread_mutex_t* stgd_lock;
pthread_mutex_t console_lock;
cglock_t ch_lock;
static pthread_rwlock_t blk_lock;
static pthread_mutex_t sshare_lock;

pthread_rwlock_t netacc_lock;
pthread_rwlock_t mining_thr_lock;
pthread_rwlock_t devices_lock;

static pthread_mutex_t lp_lock;
static pthread_cond_t lp_cond;

pthread_mutex_t restart_lock;
pthread_cond_t restart_cond;

pthread_cond_t gws_cond;

double total_mhashes_done;
static struct timeval total_tv_start, total_tv_end;

cglock_t control_lock;
pthread_mutex_t stats_lock;

int hw_errors;
int total_accepted, total_rejected, total_diff1;
int total_getworks, total_stale, total_discarded;
double total_diff_accepted, total_diff_rejected, total_diff_stale;
static int staged_rollable;
unsigned int new_blocks;
static unsigned int work_block;
unsigned int found_blocks;

unsigned int local_work;
unsigned int total_go, total_ro;

struct pool** pools;
static struct pool* currentpool = NULL;

int total_pools, enabled_pools;
enum pool_strategy pool_strategy = POOL_FAILOVER;
int opt_rotate_period;
static int total_urls, total_users, total_passes, total_userpasses;

static
#ifndef HAVE_CURSES
    const
#endif
    bool curses_active;

static char current_block[65];

/* Protected by ch_lock */
static char* current_hash;
char* current_fullhash;

static char datestamp[40];
static char blocktime[32];
struct timeval block_timeval;
static char best_share[8] = "0";
double current_block_diff;
double current_share_diff;
static char block_diff[8];
static char share_diff[8];
double best_diff = 0;

struct block
{
    uint8_t commitment_hex[65];
    UT_hash_handle hh;
    int block_no;
};

static struct block* blocks = NULL;


int swork_id;

/* For creating a hash database of stratum shares submitted that have not had
 * a response yet */
struct stratum_share
{
    UT_hash_handle hh;
    bool block;
    struct work* work;
    int id;
    time_t sshare_time;
};

static struct stratum_share* stratum_shares = NULL;

char* opt_socks_proxy = NULL;

static const char def_conf[] = "cgminer.conf";
static char* default_config;
static bool config_loaded;
static int include_count;
#define JSON_INCLUDE_CONF   "include"
#define JSON_LOAD_ERROR     "JSON decode of file '%s' failed\n %s"
#define JSON_LOAD_ERROR_LEN strlen(JSON_LOAD_ERROR)
#define JSON_MAX_DEPTH      10
#define JSON_MAX_DEPTH_ERR  "Too many levels of JSON includes (limit 10) or a loop"

#if defined(unix)
static char* opt_stderr_cmd = NULL;
static int forkpid;
#endif // defined(unix)

bool ping = true;

struct sigaction termhandler, inthandler;

struct thread_q* getq;

static int total_work = 0;
struct work* staged_work = NULL;

struct schedtime
{
    bool enable;
    struct tm tm;
};

struct schedtime schedstart;
struct schedtime schedstop;
bool sched_paused;

secp256k1_context* secp256k1_context_sign = NULL;

static bool time_before(struct tm* tm1, struct tm* tm2)
{
    if (tm1->tm_hour < tm2->tm_hour)
        return true;
    if (tm1->tm_hour == tm2->tm_hour && tm1->tm_min < tm2->tm_min)
        return true;
    return false;
}

static bool should_run(void)
{
    struct timeval tv;
    struct tm* tm;

    if (!schedstart.enable && !schedstop.enable)
        return true;

    gettimeofday(&tv, NULL);
    tm = localtime(&tv.tv_sec);
    if (schedstart.enable)
    {
        if (!schedstop.enable)
        {
            if (time_before(tm, &schedstart.tm))
                return false;

            /* This is a once off event with no stop time set */
            schedstart.enable = false;
            return true;
        }
        if (time_before(&schedstart.tm, &schedstop.tm))
        {
            if (time_before(tm, &schedstop.tm) && !time_before(tm, &schedstart.tm))
                return true;
            return false;
        } /* Times are reversed */
        if (time_before(tm, &schedstart.tm))
        {
            if (time_before(tm, &schedstop.tm))
                return true;
            return false;
        }
        return true;
    }
    /* only schedstop.enable == true */
    if (!time_before(tm, &schedstop.tm))
        return false;
    return true;
}

void get_datestamp(char* f, struct timeval* tv)
{
    struct tm* tm;

    tm = localtime(&tv->tv_sec);
    sprintf(f, "[%d-%02d-%02d %02d:%02d:%02d]", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour,
        tm->tm_min, tm->tm_sec);
}

void get_timestamp(char* f, struct timeval* tv)
{
    struct tm* tm;

    tm = localtime(&tv->tv_sec);
    sprintf(f, "[%02d:%02d:%02d]", tm->tm_hour, tm->tm_min, tm->tm_sec);
}

static char exit_buf[512];

static void applog_and_exit(const char* fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(exit_buf, sizeof(exit_buf), fmt, ap);
	va_end(ap);
	_applog(LOG_ERR, exit_buf, true);
    exit(1);
}

static pthread_mutex_t sharelog_lock;
static FILE* sharelog_file = NULL;

struct thr_info* get_thread(int thr_id)
{
    struct thr_info* thr;

    rd_lock(&mining_thr_lock);
    thr = mining_thr[thr_id];
    rd_unlock(&mining_thr_lock);
    return thr;
}

static struct cgpu_info* get_thr_cgpu(int thr_id)
{
    struct thr_info* thr = get_thread(thr_id);

    return thr->cgpu;
}

struct cgpu_info* get_devices(int id)
{
    struct cgpu_info* cgpu;

    rd_lock(&devices_lock);
    cgpu = devices[id];
    rd_unlock(&devices_lock);
    return cgpu;
}

static void sharelog(const char* disposition, const struct work* work)
{
    char* data;
    char* target;
    struct cgpu_info* cgpu;
    unsigned long int t;
    struct pool* pool;
    int thr_id, rv;
    char s[1024];
    size_t ret;

    if (!sharelog_file)
        return;

    thr_id = work->thr_id;
    cgpu = get_thr_cgpu(thr_id);
    pool = work->pool;
    t = (unsigned long int)(work->tv_work_found.tv_sec);
    target = bin2hex(work->target, sizeof(work->target));
    data = bin2hex(work->headerCommitment, sizeof(work->headerCommitment));

    // timestamp,disposition,target,pool,dev,thr,sharehash,sharedata
    rv = snprintf(s, sizeof(s), "%lu,%s,%s,%s,%s%u,%u,%s\n", t, disposition, target, pool->rpc_url,
        cgpu->drv->name, cgpu->device_id, thr_id, data);
    free(data);
    if (rv >= (int)(sizeof(s)))
        s[sizeof(s) - 1] = '\0';
    else if (rv < 0)
    {
        applog(LOG_ERR, "sharelog printf error");
        return;
    }

    mutex_lock(&sharelog_lock);
    ret = fwrite(s, rv, 1, sharelog_file);
    fflush(sharelog_file);
    mutex_unlock(&sharelog_lock);
    if (ret != 1)
        applog(LOG_ERR, "sharelog fwrite error");
}

static char* getwork_req = "{\"method\": \"getwork\", \"params\": [], \"id\":0}\n";

/* Return value is ignored if not called from add_pool_details */
struct pool* add_pool(void)
{
    struct pool* pool;

    pool = calloc(sizeof(struct pool), 1);
    if (!pool)
        nxquit(1, "Failed to malloc pool in add_pool");
    pool->pool_no = pool->prio = total_pools;
    pools = realloc(pools, sizeof(struct pool*) * (total_pools + 2));
    pools[total_pools++] = pool;
    mutex_init(&pool->pool_lock);
    if (unlikely(pthread_cond_init(&pool->cr_cond, NULL)))
        nxquit(1, "Failed to pthread_cond_init in add_pool");
    cglock_init(&pool->data_lock);
    mutex_init(&pool->stratum_lock);
    INIT_LIST_HEAD(&pool->curlring);

    /* Make sure the pool doesn't think we've been idle since time 0 */
    pool->tv_idle.tv_sec = ~0UL;

    pool->rpc_req = getwork_req;
    pool->rpc_proxy = NULL;

    return pool;
}

/* Pool variant of test and set */
static bool pool_tset(struct pool* pool, bool* var)
{
    bool ret;

    mutex_lock(&pool->pool_lock);
    ret = *var;
    *var = true;
    mutex_unlock(&pool->pool_lock);
    return ret;
}

bool pool_tclear(struct pool* pool, bool* var)
{
    bool ret;

    mutex_lock(&pool->pool_lock);
    ret = *var;
    *var = false;
    mutex_unlock(&pool->pool_lock);
    return ret;
}

struct pool* current_pool(void)
{
    struct pool* pool;

    cg_rlock(&control_lock);
    pool = currentpool;
    cg_runlock(&control_lock);
    return pool;
}

char* set_int_range(const char* arg, int* i, int min, int max)
{
    char* err = opt_set_intval(arg, i);

    if (err)
        return err;

    if (*i < min || *i > max)
        return "Value out of range";

    return NULL;
}

static char* set_int_0_to_9999(const char* arg, int* i)
{
    return set_int_range(arg, i, 0, 9999);
}

static char* set_int_1_to_65535(const char* arg, int* i)
{
    return set_int_range(arg, i, 1, 65535);
}

static char* set_int_0_to_10(const char* arg, int* i)
{
    return set_int_range(arg, i, 0, 10);
}

static char* set_int_1_to_10(const char* arg, int* i)
{
    return set_int_range(arg, i, 1, 10);
}

static char* set_devices(char* arg)
{
    int i = strtol(arg, &arg, 0);

    if (*arg)
    {
        if (*arg == '?')
        {
            devices_enabled = -1;
            return NULL;
        }
        return "Invalid device number";
    }

    if (i < 0 || i >= (int)(sizeof(devices_enabled) * 8) - 1)
        return "Invalid device number";
    devices_enabled |= 1 << i;
    return NULL;
}

static char* set_balance(enum pool_strategy* strategy)
{
    *strategy = POOL_BALANCE;
    return NULL;
}

static char* set_loadbalance(enum pool_strategy* strategy)
{
    *strategy = POOL_LOADBALANCE;
    return NULL;
}

static char* set_rotate(const char* arg, int* i)
{
    pool_strategy = POOL_ROTATE;
    return set_int_range(arg, i, 0, 9999);
}

static char* set_rr(enum pool_strategy* strategy)
{
    *strategy = POOL_ROUNDROBIN;
    return NULL;
}

/* Detect that url is for a stratum protocol either via the presence of
 * stratum+tcp or by detecting a stratum server response */
bool detect_stratum(struct pool* pool, char* url)
{
    if (!extract_sockaddr(pool, url))
        return false;

    if (!strncasecmp(url, "stratum+tcp://", 14))
    {
        pool->rpc_url = strdup(url);
        pool->has_stratum = true;
        pool->stratum_url = pool->sockaddr_url;
        return true;
    }

    return false;
}

static char* set_url(char* arg)
{
    struct pool* pool;

    total_urls++;
    if (total_urls > total_pools)
        add_pool();
    pool = pools[total_urls - 1];

    if (detect_stratum(pool, arg))
        return NULL;

    opt_set_charp(arg, &pool->rpc_url);
    if (strncmp(arg, "http://", 7) && strncmp(arg, "https://", 8))
    {
        char* httpinput;
        httpinput = malloc(255);
        if (!httpinput)
        {
            nxquit(1, "Failed to malloc httpinput");
        }
        strcpy(httpinput, "http://");
        strncat(httpinput, arg, 248);
        pool->rpc_url = httpinput;
    }

    return NULL;
}

static char* set_user(const char* arg)
{
    struct pool* pool;

    if (total_userpasses)
        return "Use only user + pass or userpass, but not both";
    total_users++;
    if (total_users > total_pools)
        add_pool();

    pool = pools[total_users - 1];
    opt_set_charp(arg, &pool->rpc_user);

    return NULL;
}

static char* set_pass(const char* arg)
{
    struct pool* pool;

    if (total_userpasses)
        return "Use only user + pass or userpass, but not both";
    total_passes++;
    if (total_passes > total_pools)
        add_pool();

    pool = pools[total_passes - 1];
    opt_set_charp(arg, &pool->rpc_pass);

    return NULL;
}

static char* set_userpass(const char* arg)
{
    struct pool* pool;
    char* updup;

    if (total_users || total_passes)
        return "Use only user + pass or userpass, but not both";
    total_userpasses++;
    if (total_userpasses > total_pools)
        add_pool();

    pool = pools[total_userpasses - 1];
    updup = strdup(arg);
    opt_set_charp(arg, &pool->rpc_userpass);
    pool->rpc_user = strtok(updup, ":");
    if (!pool->rpc_user)
        return "Failed to find : delimited user info";
    pool->rpc_pass = strtok(NULL, ":");
    if (!pool->rpc_pass)
        return "Failed to find : delimited pass info";

    return NULL;
}

static char* enable_debug(bool* flag)
{
    *flag = true;
    /* Turn on verbose output, too. */
    opt_log_output = true;
    return NULL;
}

static char* set_schedtime(const char* arg, struct schedtime* st)
{
    if (sscanf(arg, "%d:%d", &st->tm.tm_hour, &st->tm.tm_min) != 2)
        return "Invalid time set, should be HH:MM";
    if (st->tm.tm_hour > 23 || st->tm.tm_min > 59 || st->tm.tm_hour < 0 || st->tm.tm_min < 0)
        return "Invalid time set.";
    st->enable = true;
    return NULL;
}

static char* set_sharelog(char* arg)
{
    char* r = "";
    long int i = strtol(arg, &r, 10);

    if ((!*r) && i >= 0 && i <= INT_MAX)
    {
        sharelog_file = fdopen((int)i, "a");
        if (!sharelog_file)
            applog(LOG_ERR, "Failed to open fd %u for share log", (unsigned int)i);
    }
    else if (!strcmp(arg, "-"))
    {
        sharelog_file = stdout;
        if (!sharelog_file)
            applog(LOG_ERR, "Standard output missing for share log");
    }
    else
    {
        sharelog_file = fopen(arg, "a");
        if (!sharelog_file)
            applog(LOG_ERR, "Failed to open %s for share log", arg);
    }

    return NULL;
}

static char* temp_cutoff_str = NULL;

char* set_temp_cutoff(char* arg)
{
    int val;

    if (!(arg && arg[0]))
        return "Invalid parameters for set temp cutoff";
    val = atoi(arg);
    if (val < 0 || val > 200)
        return "Invalid value passed to set temp cutoff";
    temp_cutoff_str = arg;

    return NULL;
}

static void load_temp_cutoffs()
{
    int i, val = 0, device = 0;
    char* nextptr;

    if (temp_cutoff_str)
    {
        for (device = 0, nextptr = strtok(temp_cutoff_str, ","); nextptr; ++device, nextptr = strtok(NULL, ","))
        {
            if (device >= total_devices)
                nxquit(1, "Too many values passed to set temp cutoff");
            val = atoi(nextptr);
            if (val < 0 || val > 200)
                nxquit(1, "Invalid value passed to set temp cutoff");

            rd_lock(&devices_lock);
            devices[device]->cutofftemp = val;
            rd_unlock(&devices_lock);
        }
    }
    else
    {
        rd_lock(&devices_lock);
        for (i = device; i < total_devices; ++i)
        {
            if (!devices[i]->cutofftemp)
                devices[i]->cutofftemp = opt_cutofftemp;
        }
        rd_unlock(&devices_lock);
        return;
    }
    if (device <= 1)
    {
        rd_lock(&devices_lock);
        for (i = device; i < total_devices; ++i)
            devices[i]->cutofftemp = val;
        rd_unlock(&devices_lock);
    }
}

static char* set_api_allow(const char* arg)
{
    opt_set_charp(arg, &opt_api_allow);

    return NULL;
}

static char* set_api_groups(const char* arg)
{
    opt_set_charp(arg, &opt_api_groups);

    return NULL;
}

static char* set_api_description(const char* arg)
{
    opt_set_charp(arg, &opt_api_description);

    return NULL;
}

static char* set_null(const char __maybe_unused* arg)
{
    return NULL;
}

/* These options are available from config file or commandline */
static struct opt_table opt_config_table[] = {
#ifdef WANT_CPUMINE
    OPT_WITH_ARG("--algo|-a",
        set_algo,
        show_algo,
        &opt_algo,
        "Specify sha256 implementation for CPU mining:\n"
        "\tauto\t\tBenchmark at startup and pick fastest algorithm"
        "\n\tc\t\tLinux kernel sha256, implemented in C"
#ifdef WANT_SSE2_4WAY
        "\n\t4way\t\ttcatm's 4-way SSE2 implementation"
#endif
#ifdef WANT_VIA_PADLOCK
        "\n\tvia\t\tVIA padlock implementation"
#endif
        "\n\tcryptopp\tCrypto++ C/C++ implementation"
#ifdef WANT_CRYPTOPP_ASM32
        "\n\tcryptopp_asm32\tCrypto++ 32-bit assembler implementation"
#endif
#ifdef WANT_X8632_SSE2
        "\n\tsse2_32\t\tSSE2 32 bit implementation for i386 machines"
#endif
#ifdef WANT_X8664_SSE2
        "\n\tsse2_64\t\tSSE2 64 bit implementation for x86_64 machines"
#endif
#ifdef WANT_X8664_SSE4
        "\n\tsse4_64\t\tSSE4.1 64 bit implementation for x86_64 machines"
#endif
#ifdef WANT_ALTIVEC_4WAY
        "\n\taltivec_4way\tAltivec implementation for PowerPC G4 and G5 machines"
#endif
        ),
#endif
    OPT_WITH_ARG("--api-allow",
        set_api_allow,
        NULL,
        NULL,
        "Allow API access only to the given list of [G:]IP[/Prefix] addresses[/subnets]"),
    OPT_WITH_ARG("--api-description",
        set_api_description,
        NULL,
        NULL,
        "Description placed in the API status header, default: cgminer version"),
    OPT_WITH_ARG("--api-groups",
        set_api_groups,
        NULL,
        NULL,
        "API one letter groups G:cmd:cmd[,P:cmd:*...] defining the cmds a groups can use"),
    OPT_WITHOUT_ARG("--api-listen", opt_set_bool, &opt_api_listen, "Enable API, default: disabled"),
    OPT_WITHOUT_ARG("--api-network",
        opt_set_bool,
        &opt_api_network,
        "Allow API (if enabled) to listen on/for any address, default: only 127.0.0.1"),
    OPT_WITH_ARG("--api-port", set_int_1_to_65535, opt_show_intval, &opt_api_port, "Port number of miner API"),
#ifdef HAVE_ADL
    OPT_WITHOUT_ARG("--auto-fan",
        opt_set_bool,
        &opt_autofan,
        "Automatically adjust all GPU fan speeds to maintain a target temperature"),
    OPT_WITHOUT_ARG("--auto-gpu",
        opt_set_bool,
        &opt_autoengine,
        "Automatically adjust all GPU engine clock speeds to maintain a target temperature"),
#endif
    OPT_WITHOUT_ARG("--balance",
        set_balance,
        &pool_strategy,
        "Change multipool strategy from failover to even share balance"),
    OPT_WITHOUT_ARG("--benchmark", opt_set_bool, &opt_benchmark, "Run cgminer in benchmark mode - produces no shares"),
#ifdef WANT_CPUMINE
    OPT_WITH_ARG("--bench-algo|-b", set_int_0_to_9999, opt_show_intval, &opt_bench_algo, opt_hidden),
#endif
#ifdef HAVE_CURSES
    OPT_WITHOUT_ARG("--compact", opt_set_bool, &opt_compact, "Use compact display without per device statistics"),
#endif
#ifdef WANT_CPUMINE
    OPT_WITH_ARG("--cpu-threads|-t",
        force_nthreads_int,
        opt_show_intval,
        &opt_n_threads,
        "Number of miner CPU threads"),
#endif
    OPT_WITHOUT_ARG("--debug|-D", enable_debug, &opt_debug, "Enable debug output"),
    OPT_WITH_ARG("--device|-d",
        set_devices,
        NULL,
        NULL,
        "Select device to use, (Use repeat -d for multiple devices, default: all)"),
    OPT_WITHOUT_ARG("--disable-gpu|-G",
        opt_set_bool,
        &opt_nogpu,
#ifdef HAVE_OPENCL
        "Disable GPU mining even if suitable devices exist"
#else
        opt_hidden
#endif
        ),
    OPT_WITHOUT_ARG("--disable-rejecting",
        opt_set_bool,
        &opt_disable_pool,
        "Automatically disable pools that continually reject shares"),
#if defined(WANT_CPUMINE) && defined(HAVE_OPENCL)
    OPT_WITHOUT_ARG("--enable-cpu|-C",
        opt_set_bool,
        &opt_usecpu,
        "Enable CPU mining with other mining (default: no CPU mining if other devices exist)"),
#endif
    OPT_WITH_ARG("--expiry|-E",
        set_int_0_to_9999,
        opt_show_intval,
        &opt_expiry,
        "Upper bound on how many seconds after getting work we consider a share from it stale"),
    OPT_WITHOUT_ARG("--failover-only",
        opt_set_bool,
        &opt_fail_only,
        "Don't leak work to backup pools when primary pool is lagging"),
#ifdef HAVE_OPENCL
    OPT_WITH_ARG("--gpu-dyninterval",
        set_int_1_to_65535,
        opt_show_intval,
        &opt_dynamic_interval,
        "Set the refresh interval in ms for GPUs using dynamic intensity"),
    OPT_WITH_ARG("--gpu-platform",
        set_int_0_to_9999,
        opt_show_intval,
        &opt_platform_id,
        "Select OpenCL platform ID to use for GPU mining"),
    OPT_WITH_ARG("--gpu-threads|-g",
        set_int_1_to_10,
        opt_show_intval,
        &opt_g_threads,
        "Number of threads per GPU (1 - 10)"),
#ifdef HAVE_ADL
    OPT_WITH_ARG("--gpu-engine",
        set_gpu_engine,
        NULL,
        NULL,
        "GPU engine (over)clock range in Mhz - one value, range and/or comma separated list (e.g. "
        "850-900,900,750-850)"),
    OPT_WITH_ARG("--gpu-fan",
        set_gpu_fan,
        NULL,
        NULL,
        "GPU fan percentage range - one value, range and/or comma separated list (e.g. 0-85,85,65)"),
    OPT_WITH_ARG("--gpu-map",
        set_gpu_map,
        NULL,
        NULL,
        "Map OpenCL to ADL device order manually, paired CSV (e.g. 1:0,2:1 maps OpenCL 1 to ADL 0, 2 to 1)"),
    OPT_WITH_ARG("--gpu-memclock",
        set_gpu_memclock,
        NULL,
        NULL,
        "Set the GPU memory (over)clock in Mhz - one value for all or separate by commas for per card"),
    OPT_WITH_ARG("--gpu-memdiff",
        set_gpu_memdiff,
        NULL,
        NULL,
        "Set a fixed difference in clock speed between the GPU and memory in auto-gpu mode"),
    OPT_WITH_ARG("--gpu-powertune",
        set_gpu_powertune,
        NULL,
        NULL,
        "Set the GPU powertune percentage - one value for all or separate by commas for per card"),
    OPT_WITHOUT_ARG("--gpu-reorder",
        opt_set_bool,
        &opt_reorder,
        "Attempt to reorder GPU devices according to PCI Bus ID"),
    OPT_WITH_ARG("--gpu-vddc",
        set_gpu_vddc,
        NULL,
        NULL,
        "Set the GPU voltage in Volts - one value for all or separate by commas for per card"),
#endif
    OPT_WITH_ARG("--intensity|-I",
        set_intensity,
        NULL,
        NULL,
        "Intensity of GPU scanning (d or " _MIN_INTENSITY_STR " -> " _MAX_INTENSITY_STR
        ", default: d to maintain desktop interactivity)"),
#endif
#if defined(HAVE_OPENCL)
    OPT_WITH_ARG("--kernel-path|-K",
        opt_set_charp,
        opt_show_charp,
        &opt_kernel_path,
        "Specify a path to where bitstream and kernel files are"),
#endif
#ifdef HAVE_OPENCL
    OPT_WITH_ARG("--kernel|-k",
        set_kernel,
        NULL,
        NULL,
        "Override sha256 kernel to use (diablo, poclbm, phatk or diakgcn) - one value or comma separated"),
#endif
    OPT_WITHOUT_ARG("--load-balance",
        set_loadbalance,
        &pool_strategy,
        "Change multipool strategy from failover to efficiency based balance"),
    OPT_WITH_ARG("--log|-l",
        set_int_0_to_9999,
        opt_show_intval,
        &opt_log_interval,
        "Interval in seconds between log output"),
#if defined(unix)
    OPT_WITH_ARG("--monitor|-m", opt_set_charp, NULL, &opt_stderr_cmd, "Use custom pipe cmd for output messages"),
#endif // defined(unix)
    OPT_WITHOUT_ARG("--net-delay",
        opt_set_bool,
        &opt_delaynet,
        "Impose small delays in networking to not overload slow routers"),
    OPT_WITHOUT_ARG("--no-adl",
        opt_set_bool,
        &opt_noadl,
#ifdef HAVE_ADL
        "Disable the ATI display library used for monitoring and setting GPU parameters"
#else
        opt_hidden
#endif
        ),
    OPT_WITHOUT_ARG("--no-pool-disable", opt_set_invbool, &opt_disable_pool, opt_hidden),
    OPT_WITHOUT_ARG("--no-restart",
        opt_set_invbool,
        &opt_restart,
#ifdef HAVE_OPENCL
        "Do not attempt to restart GPUs that hang"
#else
        opt_hidden
#endif
        ),
    OPT_WITHOUT_ARG("--no-submit-stale",
        opt_set_invbool,
        &opt_submit_stale,
        "Don't submit shares if they are detected as stale"),
    OPT_WITH_ARG("--pass|-p", set_pass, NULL, NULL, "Password for bitcoin JSON-RPC server"),
    OPT_WITHOUT_ARG("--per-device-stats",
        opt_set_bool,
        &want_per_device_stats,
        "Force verbose mode and output per-device statistics"),
    OPT_WITHOUT_ARG("--protocol-dump|-P", opt_set_bool, &opt_protocol, "Verbose dump of protocol-level activities"),
    OPT_WITH_ARG("--queue|-Q",
        set_int_0_to_9999,
        opt_show_intval,
        &opt_queue,
        "Minimum number of work items to have queued (0+)"),
    OPT_WITHOUT_ARG("--quiet|-q", opt_set_bool, &opt_quiet, "Disable logging output, display status and errors"),
    OPT_WITHOUT_ARG("--real-quiet", opt_set_bool, &opt_realquiet, "Disable all output"),
    OPT_WITHOUT_ARG("--remove-disabled",
        opt_set_bool,
        &opt_removedisabled,
        "Remove disabled devices entirely, as if they didn't exist"),
    OPT_WITH_ARG("--retries", set_null, NULL, NULL, opt_hidden),
    OPT_WITH_ARG("--retry-pause", set_null, NULL, NULL, opt_hidden),
    OPT_WITH_ARG("--rotate",
        set_rotate,
        opt_show_intval,
        &opt_rotate_period,
        "Change multipool strategy from failover to regularly rotate at N minutes"),
    OPT_WITHOUT_ARG("--round-robin",
        set_rr,
        &pool_strategy,
        "Change multipool strategy from failover to round robin on failure"),
    OPT_WITH_ARG("--scan-time|-s",
        set_int_0_to_9999,
        opt_show_intval,
        &opt_scantime,
        "Upper bound on time spent scanning current work, in seconds"),
    OPT_WITH_ARG("--sched-start",
        set_schedtime,
        NULL,
        &schedstart,
        "Set a time of day in HH:MM to start mining (a once off without a stop time)"),
    OPT_WITH_ARG("--sched-stop",
        set_schedtime,
        NULL,
        &schedstop,
        "Set a time of day in HH:MM to stop mining (will quit without a start time)"),
    OPT_WITH_ARG("--sharelog", set_sharelog, NULL, NULL, "Append share log to file"),
    OPT_WITH_ARG("--shares", opt_set_intval, NULL, &opt_shares, "Quit after mining N shares (default: unlimited)"),
    OPT_WITH_ARG("--socks-proxy", opt_set_charp, NULL, &opt_socks_proxy, "Set socks4 proxy (host:port)"),
#ifdef HAVE_SYSLOG_H
    OPT_WITHOUT_ARG("--syslog",
        opt_set_bool,
        &use_syslog,
        "Use system log for output messages (default: standard error)"),
#endif
#if defined(HAVE_ADL)
    OPT_WITH_ARG("--temp-cutoff",
        set_temp_cutoff,
        opt_show_intval,
        &opt_cutofftemp,
        "Temperature where a device will be automatically disabled, one value or comma separated list"),
#endif
#ifdef HAVE_ADL
    OPT_WITH_ARG("--temp-hysteresis",
        set_int_1_to_10,
        opt_show_intval,
        &opt_hysteresis,
        "Set how much the temperature can fluctuate outside limits when automanaging speeds"),
    OPT_WITH_ARG("--temp-overheat",
        set_temp_overheat,
        opt_show_intval,
        &opt_overheattemp,
        "Overheat temperature when automatically managing fan and GPU speeds, one value or comma separated list"),
    OPT_WITH_ARG("--temp-target",
        set_temp_target,
        opt_show_intval,
        &opt_targettemp,
        "Target temperature when automatically managing fan and GPU speeds, one value or comma separated list"),
#endif
    OPT_WITHOUT_ARG("--text-only|-T",
        opt_set_invbool,
        &use_curses,
#ifdef HAVE_CURSES
        "Disable ncurses formatted screen output"
#else
        opt_hidden
#endif
        ),
    OPT_WITH_ARG("--url|-o", set_url, NULL, NULL, "URL for bitcoin JSON-RPC server"),
    OPT_WITH_ARG("--user|-u", set_user, NULL, NULL, "Username for bitcoin JSON-RPC server"),
#ifdef HAVE_OPENCL
    OPT_WITH_ARG("--vectors|-v",
        set_vector,
        NULL,
        NULL,
        "Override detected optimal vector (1, 2 or 4) - one value or comma separated list"),
#endif
    OPT_WITHOUT_ARG("--verbose",
        opt_set_bool,
        &opt_log_output,
        "Log verbose output to stderr as well as status output"),
#ifdef HAVE_OPENCL
    OPT_WITH_ARG("--worksize|-w",
        set_worksize,
        NULL,
        NULL,
        "Override detected optimal worksize - one value or comma separated list"),
#endif
    OPT_WITH_ARG("--userpass|-O", set_userpass, NULL, NULL, "Username:Password pair for bitcoin JSON-RPC server"),
    OPT_WITHOUT_ARG("--worktime", opt_set_bool, &opt_worktime, "Display extra work time debug information"),
    OPT_WITH_ARG("--pools", opt_set_bool, NULL, NULL, opt_hidden), OPT_ENDTABLE};

static char* load_config(const char* arg, void __maybe_unused* unused);

static int fileconf_load;

static char* parse_config(json_t* config, bool fileconf)
{
    static char err_buf[200];
    struct opt_table* opt;
    json_t* val;

    if (fileconf && !fileconf_load)
        fileconf_load = 1;

    for (opt = opt_config_table; opt->type != OPT_END; opt++)
    {
        char *p, *name;

        /* We don't handle subtables. */
        assert(!(opt->type & OPT_SUBTABLE));

        /* Pull apart the option name(s). */
        name = strdup(opt->names);
        for (p = strtok(name, "|"); p; p = strtok(NULL, "|"))
        {
            char* err = NULL;

            /* Ignore short options. */
            if (p[1] != '-')
                continue;

            val = json_object_get(config, p + 2);
            if (!val)
                continue;

            if ((opt->type & OPT_HASARG) && json_is_string(val))
            {
                err = opt->cb_arg(json_string_value(val), opt->u.arg);
            }
            else if ((opt->type & OPT_HASARG) && json_is_array(val))
            {
                int n, size = json_array_size(val);

                for (n = 0; n < size && !err; n++)
                {
                    if (json_is_string(json_array_get(val, n)))
                        err = opt->cb_arg(json_string_value(json_array_get(val, n)), opt->u.arg);
                    else if (json_is_object(json_array_get(val, n)))
                        err = parse_config(json_array_get(val, n), false);
                }
            }
            else if ((opt->type & OPT_NOARG) && json_is_true(val))
                err = opt->cb(opt->u.arg);
            else
                err = "Invalid value";

            if (err)
            {
                /* Allow invalid values to be in configuration
                 * file, just skipping over them provided the
                 * JSON is still valid after that. */
                if (fileconf)
                {
                    applog(LOG_ERR, "Invalid config option %s: %s", p, err);
                    fileconf_load = -1;
                }
                else
                {
                    sprintf(err_buf, "Parsing JSON option %s: %s", p, err);
                    return err_buf;
                }
            }
        }
        free(name);
    }

    val = json_object_get(config, JSON_INCLUDE_CONF);
    if (val && json_is_string(val))
        return load_config(json_string_value(val), NULL);

    return NULL;
}

char* cnfbuf = NULL;

static char* load_config(const char* arg, void __maybe_unused* unused)
{
    json_error_t err;
    json_t* config;
    char* json_error;

    if (!cnfbuf)
        cnfbuf = strdup(arg);

    if (++include_count > JSON_MAX_DEPTH)
        return JSON_MAX_DEPTH_ERR;

    config = json_load_file(arg, 0, &err);
    if (!json_is_object(config))
    {
        json_error = malloc(JSON_LOAD_ERROR_LEN + strlen(arg) + strlen(err.text));
        if (!json_error)
            nxquit(1, "Malloc failure in json error");

        sprintf(json_error, JSON_LOAD_ERROR, arg, err.text);
        return json_error;
    }

    config_loaded = true;

    /* Parse the config now, so we can override it.  That can keep pointers
     * so don't free config object. */
    return parse_config(config, true);
}

static char* set_default_config(const char* arg)
{
    opt_set_charp(arg, &default_config);

    return NULL;
}

void default_save_file(char* filename);

static void load_default_config(void)
{
    cnfbuf = malloc(PATH_MAX);

    default_save_file(cnfbuf);

    if (!access(cnfbuf, R_OK))
        load_config(cnfbuf, NULL);
    else
    {
        free(cnfbuf);
        cnfbuf = NULL;
    }
}

extern const char* opt_argv0;

static char* opt_verusage_and_exit(const char* extra)
{
    printf("%s\nBuilt with "
#ifdef HAVE_OPENCL
           "GPU "
#endif
#ifdef WANT_CPUMINE
           "CPU "
#endif
           "mining support.\n",
        packagename);
    printf("%s", opt_usage(opt_argv0, extra));
    fflush(stdout);
    exit(0);
}

#if defined(HAVE_OPENCL)
char* display_devs(int* ndevs)
{
    *ndevs = 0;
#ifdef HAVE_OPENCL
    print_ndevs(ndevs);
#endif
    exit(*ndevs);
}
#endif

/* These options are available from commandline only */
static struct opt_table opt_cmdline_table[] = {OPT_WITH_ARG("--config|-c",
                                                   load_config,
                                                   NULL,
                                                   NULL,
                                                   "Load a JSON-format configuration file\n"
                                                   "See example.conf for an example configuration."),
    OPT_WITH_ARG("--default-config",
        set_default_config,
        NULL,
        NULL,
        "Specify the filename of the default config file\n"
        "Loaded at start and used when saving without a name."),
    OPT_WITHOUT_ARG("--help|-h", opt_verusage_and_exit, NULL, "Print this message"),
#if defined(HAVE_OPENCL)
    OPT_WITHOUT_ARG("--ndevs|-n",
        display_devs,
        &nDevs,
        "Display "
#ifdef HAVE_OPENCL
        "number of detected GPUs, OpenCL platform information, "
#endif
        "and exit"),
#endif
    OPT_WITHOUT_ARG("--version|-V", opt_version_and_exit, packagename, "Display version and exit"), OPT_ENDTABLE};

static bool jobj_binary(const json_t* obj, const char* key, void* buf, size_t buflen, bool required)
{
    const char* hexstr;
    json_t* tmp;

    tmp = json_object_get(obj, key);
    if (unlikely(!tmp))
    {
        if (unlikely(required))
            applog(LOG_ERR, "JSON key '%s' not found", key);
        return false;
    }
    hexstr = json_string_value(tmp);
    if (unlikely(!hexstr))
    {
        applog(LOG_ERR, "JSON key '%s' is not a string", key);
        return false;
    }
    if (!hex2bin(buf, hexstr, buflen))
        return false;

    return true;
}

static struct work* make_work(void)
{
    struct work* work = calloc(1, sizeof(struct work));

    if (unlikely(!work))
        nxquit(1, "Failed to calloc work in make_work");
    cg_wlock(&control_lock);
    work->id = total_work++;
    cg_wunlock(&control_lock);
    return work;
}

/* This is the central place all work that is about to be retired should be
 * cleaned to remove any dynamically allocated arrays within the struct */
void clean_work(struct work* work)
{
    free(work->job_id);
    free(work->ntime);
    memset(work, 0, sizeof(struct work));
}

/* All dynamically allocated work structs should be freed here to not leak any
 * ram from arrays allocated within the work struct */
void free_work(struct work* work)
{
    clean_work(work);
    free(work);
}

static char* workpadding =
    "000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000";

int dev_from_id(int thr_id)
{
    struct cgpu_info* cgpu = get_thr_cgpu(thr_id);

    return cgpu->device_id;
}

/* Make the change in the recent value adjust dynamically when the difference
 * is large, but damp it when the values are closer together. This allows the
 * value to change quickly, but not fluctuate too dramatically when it has
 * stabilised. */
void decay_time(double* f, double fadd)
{
    double ratio = 0;

    if (likely(*f > 0))
    {
        ratio = fadd / *f;
        if (ratio > 1)
            ratio = 1 / ratio;
    }

    if (ratio > 0.63)
        *f = (fadd * 0.58 + *f) / 1.58;
    else
        *f = (fadd + *f * 0.58) / 1.58;
}

static int __total_staged(void)
{
    return HASH_COUNT(staged_work);
}

static int total_staged(void)
{
    int ret;

    mutex_lock(stgd_lock);
    ret = __total_staged();
    mutex_unlock(stgd_lock);
    return ret;
}

#ifdef HAVE_CURSES
WINDOW *mainwin, *statuswin, *logwin;
#endif
double total_secs = 1.0;
static char statusline[256];
/* logstart is where the log window should start */
static int devcursor, logstart, logcursor;
#ifdef HAVE_CURSES
/* statusy is where the status window goes up to in cases where it won't fit at startup */
static int statusy;
#endif
#ifdef HAVE_OPENCL
struct cgpu_info gpus[MAX_GPUDEVICES]; /* Maximum number apparently possible */
#endif
struct cgpu_info* cpus;

#ifdef HAVE_CURSES
static inline void unlock_curses(void)
{
    mutex_unlock(&console_lock);
}

static inline void lock_curses(void)
{
    mutex_lock(&console_lock);
}

static bool curses_active_locked(void)
{
    bool ret;

    lock_curses();
    ret = curses_active;
    if (!ret)
        unlock_curses();
    return ret;
}
#endif

void tailsprintf(char* f, const char* fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsprintf(f + strlen(f), fmt, ap);
    va_end(ap);
}


/* Convert a double value into a truncated string for displaying with its
 * associated suitable for Mega, Giga etc. Buf array needs to be long enough */
static void suffix_string_double(double val, char* buf, int sigdigits)
{
    const double dkilo = 1000.0;
    const double kilo = (double)1000ull;
    const double mega = (double)1000000ull;
    const double giga = (double)1000000000ull;
    const double tera = (double)1000000000000ull;
    const double peta = (double)1000000000000000ull;
    const double exa =  (double)1000000000000000000ull;
    char suffix[2] = "";
    bool decimal = true;
    double dval;

    if (val >= exa)
    {
        val /= peta;
        dval = val / dkilo;
        sprintf(suffix, "E");
    }
    else if (val >= peta)
    {
        val /= tera;
        dval = val / dkilo;
        sprintf(suffix, "P");
    }
    else if (val >= tera)
    {
        val /= giga;
        dval = val / dkilo;
        sprintf(suffix, "T");
    }
    else if (val >= giga)
    {
        val /= mega;
        dval = val / dkilo;
        sprintf(suffix, "G");
    }
    else if (val >= mega)
    {
        val /= kilo;
        dval = val / dkilo;
        sprintf(suffix, "M");
    }
    else if (val >= kilo)
    {
        dval = val / dkilo;
        sprintf(suffix, "K");
    }
    else
    {
        dval = val;
        decimal = false;
    }

    if (!sigdigits)
    {
        if (decimal)
            sprintf(buf, "%.3g%s", dval, suffix);
        else
            sprintf(buf, "%d%s", (unsigned int)dval, suffix);
    }
    else
    {
        /* Always show sigdigits + 1, padded on right with zeroes
         * followed by suffix */
        int ndigits = sigdigits - 1 - (dval > 0.0 ? floor(log10(dval)) : 0);

        sprintf(buf, "%*.*f%s", sigdigits + 1, ndigits, dval, suffix);
    }
}


/* Convert a uint64_t value into a truncated string for displaying with its
 * associated suitable for Mega, Giga etc. Buf array needs to be long enough */
static void suffix_string(uint64_t val, char* buf, int sigdigits)
{
    const double dkilo = 1000.0;
    const uint64_t kilo = 1000ull;
    const uint64_t mega = 1000000ull;
    const uint64_t giga = 1000000000ull;
    const uint64_t tera = 1000000000000ull;
    const uint64_t peta = 1000000000000000ull;
    const uint64_t exa = 1000000000000000000ull;
    char suffix[2] = "";
    bool decimal = true;
    double dval;

    if (val >= exa)
    {
        val /= peta;
        dval = (double)val / dkilo;
        sprintf(suffix, "E");
    }
    else if (val >= peta)
    {
        val /= tera;
        dval = (double)val / dkilo;
        sprintf(suffix, "P");
    }
    else if (val >= tera)
    {
        val /= giga;
        dval = (double)val / dkilo;
        sprintf(suffix, "T");
    }
    else if (val >= giga)
    {
        val /= mega;
        dval = (double)val / dkilo;
        sprintf(suffix, "G");
    }
    else if (val >= mega)
    {
        val /= kilo;
        dval = (double)val / dkilo;
        sprintf(suffix, "M");
    }
    else if (val >= kilo)
    {
        dval = (double)val / dkilo;
        sprintf(suffix, "K");
    }
    else
    {
        dval = val;
        decimal = false;
    }

    if (!sigdigits)
    {
        if (decimal)
            sprintf(buf, "%.3g%s", dval, suffix);
        else
            sprintf(buf, "%d%s", (unsigned int)dval, suffix);
    }
    else
    {
        /* Always show sigdigits + 1, padded on right with zeroes
         * followed by suffix */
        int ndigits = sigdigits - 1 - (dval > 0.0 ? floor(log10(dval)) : 0);

        sprintf(buf, "%*.*f%s", sigdigits + 1, ndigits, dval, suffix);
    }
}

static void get_statline(char* buf, struct cgpu_info* cgpu)
{
    char displayed_hashes[16], displayed_rolling[16];
    uint64_t dh64, dr64;

    dh64 = (double)cgpu->total_mhashes / total_secs * 1000000ull;
    dr64 = (double)cgpu->rolling * 1000000ull;
    suffix_string(dh64, displayed_hashes, 4);
    suffix_string(dr64, displayed_rolling, 4);

    sprintf(buf, "%s%d ", cgpu->drv->name, cgpu->device_id);
    cgpu->drv->get_statline_before(buf, cgpu);
    tailsprintf(buf, "(%ds):%s (avg):%sh/s | A:%d R:%d HW:%d U:%.1f/m", opt_log_interval, displayed_rolling,
        displayed_hashes, cgpu->accepted, cgpu->rejected, cgpu->hw_errors, cgpu->utility);
    cgpu->drv->get_statline(buf, cgpu);
}

static void text_print_status(int thr_id)
{
    struct cgpu_info* cgpu;
    char logline[256];

    cgpu = get_thr_cgpu(thr_id);
    if (cgpu)
    {
        get_statline(logline, cgpu);
        printf("%s\n", logline);
    }
}

#ifdef HAVE_CURSES
/* Must be called with curses mutex lock held and curses_active */
static void curses_print_status(void)
{
    struct pool* pool = current_pool();

    wattron(statuswin, A_BOLD);
    mvwprintw(statuswin, 0, 0, " " PACKAGE_NAME " version " PACKAGE_VERSION " - Started: %s", datestamp);
#ifdef WANT_CPUMINE
    if (opt_n_threads)
        wprintw(statuswin, " CPU Algo: %s", algo_names[opt_algo]);
#endif
    wattroff(statuswin, A_BOLD);
    mvwhline(statuswin, 1, 0, '-', 80);
    mvwprintw(statuswin, 2, 0, " %s", statusline);
    wclrtoeol(statuswin);
    mvwprintw(statuswin, 3, 0, " ST: %d  SS: %d  DW: %d  NB: %d  LW: %d  GF: %d  RF: %d  WU: %.1f", total_staged(),
        total_stale, total_discarded, new_blocks, local_work, total_go, total_ro, total_diff1 / total_secs * 60);
    wclrtoeol(statuswin);
    if ((pool_strategy == POOL_LOADBALANCE || pool_strategy == POOL_BALANCE) && total_pools > 1)
    {
        mvwprintw(statuswin, 4, 0, " Connected to multiple pools without LP");
    }
    else // (pool->has_stratum)
    {
        mvwprintw(statuswin, 4, 0, " Connected to %s diff %s with stratum as user %s", pool->sockaddr_url, pool->diff,
            pool->rpc_user);
    }
    wclrtoeol(statuswin);
    cg_rlock(&ch_lock);
    mvwprintw(statuswin, 5, 0, " Block: %s...  Block Diff:%s  Started: %s  Share Diff: %s   ", current_hash, block_diff,
        blocktime, share_diff);
    cg_runlock(&ch_lock);
    mvwhline(statuswin, 6, 0, '-', 80);
    mvwhline(statuswin, statusy - 1, 0, '-', 80);
    mvwprintw(statuswin, devcursor - 1, 1, "[P]ool management %s[S]ettings [D]isplay options [Q]uit",
        have_opencl ? "[G]PU management " : "");
}

static void adj_width(int var, int* length)
{
    if ((int)(log10(var) + 1) > *length)
        (*length)++;
}

static int dev_width;

static void curses_print_devstatus(int thr_id)
{
    static int awidth = 1, rwidth = 1, hwwidth = 1, uwidth = 1;
    struct cgpu_info* cgpu;
    char logline[256];
    char displayed_hashes[16], displayed_rolling[16];
    uint64_t dh64, dr64;

    if (opt_compact)
        return;

    cgpu = get_thr_cgpu(thr_id);

    if (cgpu->cgminer_id >= start_devices || devcursor + cgpu->cgminer_id > LINES - 2)
        return;

    cgpu->utility = cgpu->accepted / total_secs * 60;

    wmove(statuswin, devcursor + cgpu->cgminer_id, 0);
    wprintw(statuswin, " %s %*d: ", cgpu->drv->name, dev_width, cgpu->device_id);
    logline[0] = '\0';
    cgpu->drv->get_statline_before(logline, cgpu);
    wprintw(statuswin, "%s", logline);

    dh64 = (double)cgpu->total_mhashes / total_secs * 1000000ull;
    dr64 = (double)cgpu->rolling * 1000000ull;
    suffix_string(dh64, displayed_hashes, 4);
    suffix_string(dr64, displayed_rolling, 4);

    if (cgpu->status == LIFE_DEAD)
        wprintw(statuswin, "DEAD  ");
    else if (cgpu->status == LIFE_SICK)
        wprintw(statuswin, "SICK  ");
    else if (cgpu->deven == DEV_DISABLED)
        wprintw(statuswin, "OFF   ");
    else if (cgpu->deven == DEV_RECOVER)
        wprintw(statuswin, "REST  ");
    else
        wprintw(statuswin, "%6s", displayed_rolling);
    adj_width(cgpu->accepted, &awidth);
    adj_width(cgpu->rejected, &rwidth);
    adj_width(cgpu->hw_errors, &hwwidth);
    adj_width(cgpu->utility, &uwidth);

    wprintw(statuswin, "/%6sh/s | A:%*d R:%*d HW:%*d U:%*.2f/m", displayed_hashes, awidth, cgpu->accepted, rwidth,
        cgpu->rejected, hwwidth, cgpu->hw_errors, uwidth + 3, cgpu->utility);

    logline[0] = '\0';
    cgpu->drv->get_statline(logline, cgpu);
    wprintw(statuswin, "%s", logline);

    wclrtoeol(statuswin);
}
#endif

static void print_status(int thr_id)
{
    if (!curses_active)
        text_print_status(thr_id);
}

#ifdef HAVE_CURSES
/* Check for window resize. Called with curses mutex locked */
static inline void change_logwinsize(void)
{
    int x, y, logx, logy;

    getmaxyx(mainwin, y, x);
    if (x < 80 || y < 25)
        return;

    if (y > statusy + 2 && statusy < logstart)
    {
        if (y - 2 < logstart)
            statusy = y - 2;
        else
            statusy = logstart;
        logcursor = statusy + 1;
        mvwin(logwin, logcursor, 0);
        wresize(statuswin, statusy, x);
    }

    y -= logcursor;
    getmaxyx(logwin, logy, logx);
    /* Detect screen size change */
    if (x != logx || y != logy)
        wresize(logwin, y, x);
}

static void check_winsizes(void)
{
    if (!use_curses)
        return;
    if (curses_active_locked())
    {
        int y, x;

        erase();
        x = getmaxx(statuswin);
        if (logstart > LINES - 2)
            statusy = LINES - 2;
        else
            statusy = logstart;
        logcursor = statusy + 1;
        wresize(statuswin, statusy, x);
        getmaxyx(mainwin, y, x);
        y -= logcursor;
        wresize(logwin, y, x);
        mvwin(logwin, logcursor, 0);
        unlock_curses();
    }
}

static void switch_compact(void)
{
    if (opt_compact)
    {
        logstart = devcursor + 1;
        logcursor = logstart + 1;
    }
    else
    {
        logstart = devcursor + total_devices + 1;
        logcursor = logstart + 1;
    }
    check_winsizes();
}
#endif

#ifdef HAVE_CURSES
/* For mandatory printing when mutex is already locked */
void _wlog(const char *str)
{
	wprintw(logwin, "%s", str);
}

/* Mandatory printing */
void _wlogprint(const char *str)
{
	if (curses_active_locked()) {
		wprintw(logwin, "%s", str);
		unlock_curses();
	}
}

bool log_curses_only(int prio, const char *datetime, const char *str)
{
	bool high_prio;

	high_prio = (prio == LOG_WARNING || prio == LOG_ERR);

	if (curses_active_locked()) {
		if (!opt_loginput || high_prio) {
			wprintw(logwin, "%s%s\n", datetime, str);
			if (high_prio) {
				touchwin(logwin);
				wrefresh(logwin);
			}
		}
		unlock_curses();
		return true;
	}
	return false;
}


void clear_logwin(void)
{
    if (curses_active_locked())
    {
        erase();
        wclear(logwin);
        unlock_curses();
    }
}
#endif

static void enable_pool(struct pool* pool)
{
    if (pool->enabled != POOL_ENABLED)
    {
        enabled_pools++;
        pool->enabled = POOL_ENABLED;
    }
}

static void disable_pool(struct pool* pool)
{
    if (pool->enabled == POOL_ENABLED)
        enabled_pools--;
    pool->enabled = POOL_DISABLED;
}

static void reject_pool(struct pool* pool)
{
    if (pool->enabled == POOL_ENABLED)
        enabled_pools--;
    pool->enabled = POOL_REJECTING;
}

/* Theoretically threads could race when modifying accepted and
 * rejected values but the chance of two submits completing at the
 * same time is zero so there is no point adding extra locking */
static void share_result(json_t* val,
    json_t* res,
    json_t* err,
    const struct work* work,
    char* hashshow,
    bool resubmit,
    char* worktime)
{
    struct pool* pool = work->pool;
    struct cgpu_info* cgpu;

    cgpu = get_thr_cgpu(work->thr_id);

    if (json_is_true(res))
    {
        mutex_lock(&stats_lock);
        cgpu->accepted++;
        total_accepted++;
        pool->accepted++;
        cgpu->diff_accepted += work->work_difficulty;
        total_diff_accepted += work->work_difficulty;
        pool->diff_accepted += work->work_difficulty;
        mutex_unlock(&stats_lock);

        pool->seq_rejects = 0;
        cgpu->last_share_pool = pool->pool_no;
        cgpu->last_share_pool_time = time(NULL);
        cgpu->last_share_diff = work->work_difficulty;
        pool->last_share_time = cgpu->last_share_pool_time;
        pool->last_share_diff = work->work_difficulty;
        applog(LOG_DEBUG, "PROOF OF WORK RESULT: true (yay!!!)");
        if (!QUIET)
        {
            if (total_pools > 1)
                applog(LOG_NOTICE, "Accepted %s %s %d pool %d %s%s", hashshow, cgpu->drv->name, cgpu->device_id,
                    work->pool->pool_no, resubmit ? "(resubmit)" : "", worktime);
            else
                applog(LOG_NOTICE, "Accepted %s %s %d %s%s", hashshow, cgpu->drv->name, cgpu->device_id,
                    resubmit ? "(resubmit)" : "", worktime);
        }
        sharelog("accept", work);
        if (opt_shares && total_accepted >= opt_shares)
        {
            applog(LOG_WARNING, "Successfully mined %d accepted shares as requested and exiting.", opt_shares);
            kill_work();
            return;
        }

        /* Detect if a pool that has been temporarily disabled for
         * continually rejecting shares has started accepting shares.
         * This will only happen with the work returned from a
         * longpoll */
        if (unlikely(pool->enabled == POOL_REJECTING))
        {
            applog(LOG_WARNING, "Rejecting pool %d now accepting shares, re-enabling!", pool->pool_no);
            enable_pool(pool);
            switch_pools(NULL);
        }
    }
    else
    {
        mutex_lock(&stats_lock);
        cgpu->rejected++;
        total_rejected++;
        pool->rejected++;
        cgpu->diff_rejected += work->work_difficulty;
        total_diff_rejected += work->work_difficulty;
        pool->diff_rejected += work->work_difficulty;
        pool->seq_rejects++;
        mutex_unlock(&stats_lock);

        applog(LOG_DEBUG, "PROOF OF WORK RESULT: false (booooo)");
        if (!QUIET)
        {
            char where[20];
            char disposition[36] = "reject";
            char reason[32];

            strcpy(reason, "");
            if (total_pools > 1)
                sprintf(where, "pool %d", work->pool->pool_no);
            else
                strcpy(where, "");

            res = json_object_get(val, "reject-reason");
            if (res)
            {
                const char* reasontmp = json_string_value(res);

                size_t reasonLen = strlen(reasontmp);
                if (reasonLen > 28)
                    reasonLen = 28;
                reason[0] = ' ';
                reason[1] = '(';
                memcpy(2 + reason, reasontmp, reasonLen);
                reason[reasonLen + 2] = ')';
                reason[reasonLen + 3] = '\0';
                memcpy(disposition + 7, reasontmp, reasonLen);
                disposition[6] = ':';
                disposition[reasonLen + 7] = '\0';
            }
            else if (work->stratum && err && json_is_array(err))
            {
                json_t* reason_val = json_array_get(err, 1);
                char* reason_str;

                if (reason_val && json_is_string(reason_val))
                {
                    reason_str = (char*)json_string_value(reason_val);
                    snprintf(reason, 31, " (%s)", reason_str);
                }
            }

            applog(LOG_NOTICE, "Rejected %s %s %d %s%s %s%s", hashshow, cgpu->drv->name, cgpu->device_id, where, reason,
                resubmit ? "(resubmit)" : "", worktime);
            sharelog(disposition, work);
        }

        /* Once we have more than a nominal amount of sequential rejects,
         * at least 10 and more than 3 mins at the current utility,
         * disable the pool because some pool error is likely to have
         * ensued. Do not do this if we know the share just happened to
         * be stale due to networking delays.
         */
        if (pool->seq_rejects > 10 && !work->stale && opt_disable_pool && enabled_pools > 1)
        {
            double utility = total_accepted / total_secs * 60;

            if (pool->seq_rejects > utility * 3)
            {
                applog(
                    LOG_WARNING, "Pool %d rejected %d sequential shares, disabling!", pool->pool_no, pool->seq_rejects);
                reject_pool(pool);
                if (pool == current_pool())
                    switch_pools(NULL);
                pool->seq_rejects = 0;
            }
        }
    }
}

static const uint64_t diffone = 0xFFFF000000000000ull;

static uint64_t calc_share_diff(const struct work *work)
{
	uint64_t *data64;
    uint64_t d64;
	char rhash[32];
	uint64_t ret;

	swab256(rhash, work->hash);
	data64 = (uint64_t *)(rhash + 4);
	d64 = be64toh(*data64);
	if (unlikely(!d64))
    {
		d64 = 1;
    }
	ret = diffone / d64;
	cg_wlock(&control_lock);
	if (ret > best_diff)
    {
		best_diff = ret;
		suffix_string_double(best_diff, best_share, 0);
	}
	if (ret > work->pool->best_diff)
    {
		work->pool->best_diff = ret;
    }
	cg_wunlock(&control_lock);
	return ret;
}

/* Specifies whether we can use this pool for work or not. */
static bool pool_unworkable(struct pool* pool)
{
    if (pool->idle)
        return true;
    if (pool->enabled != POOL_ENABLED)
        return true;
    if (pool->has_stratum && !pool->stratum_active)
        return true;
    return false;
}

/* In balanced mode, the amount of diff1 solutions per pool is monitored as a
 * rolling average per 10 minutes and if pools start getting more, it biases
 * away from them to distribute work evenly. The share count is reset to the
 * rolling average every 10 minutes to not send all work to one pool after it
 * has been disabled/out for an extended period. */
static struct pool* select_balanced(struct pool* cp)
{
    int i, lowest = cp->shares;
    struct pool* ret = cp;

    for (i = 0; i < total_pools; i++)
    {
        struct pool* pool = pools[i];

        if (pool_unworkable(pool))
            continue;
        if (pool->shares < lowest)
        {
            lowest = pool->shares;
            ret = pool;
        }
    }

    ret->shares++;
    return ret;
}

/* Select any active pool in a rotating fashion when loadbalance is chosen */
static inline struct pool* select_pool(bool lagging)
{
    static int rotating_pool = 0;
    struct pool *pool, *cp;
    int tested;

    cp = current_pool();

    if (pool_strategy == POOL_BALANCE)
        return select_balanced(cp);

    if (pool_strategy != POOL_LOADBALANCE && (!lagging || opt_fail_only))
        pool = cp;
    else
        pool = NULL;

    /* Try to find the first pool in the rotation that is usable */
    tested = 0;
    while (!pool && tested++ < total_pools)
    {
        if (++rotating_pool >= total_pools)
            rotating_pool = 0;
        pool = pools[rotating_pool];
        if (!pool_unworkable(pool))
            break;
        pool = NULL;
    }
    /* If still nothing is usable, use the current pool */
    if (!pool)
        pool = cp;

    return pool;
}

static double DIFFEXACTONE = 26959946667150639794667015087019630673637144422540572481103610249215.0;

/*
 * Calculate the work share difficulty
 */
static void calc_diff(struct work *work, double known)
{
	struct cgminer_pool_stats *pool_stats = &(work->pool->cgminer_pool_stats);
	double difficulty;

	if (known == 0.0)
    {
		double targ = 0;
		int i;

		for (i = 31; i >= 0; i--)
        {
			targ *= 256;
			targ += work->target[i];
		}

		work->work_difficulty = DIFFEXACTONE / (targ ? : DIFFEXACTONE);
	}
    else
    {
		work->work_difficulty = known;
    }
	difficulty = work->work_difficulty;

	pool_stats->last_diff = difficulty;
	suffix_string_double(difficulty, work->pool->diff, 0);

	if (difficulty == pool_stats->min_diff)
    {
		pool_stats->min_diff_count++;
    }
	else if (difficulty < pool_stats->min_diff || pool_stats->min_diff == 0)
    {
		pool_stats->min_diff = difficulty;
		pool_stats->min_diff_count = 1;
	}

	if (difficulty == pool_stats->max_diff)
    {
		pool_stats->max_diff_count++;
    }
	else if (difficulty > pool_stats->max_diff)
    {
		pool_stats->max_diff = difficulty;
		pool_stats->max_diff_count = 1;
	}
}

static void get_benchmark_work(struct work* work)
{
    // Use a random work block pulled from a pool
    static uint8_t bench_block[] = {CGMINER_BENCHMARK_BLOCK};

    size_t bench_size = sizeof(*work);
    size_t work_size = sizeof(bench_block);
    size_t min_size = (work_size < bench_size ? work_size : bench_size);
    memset(work, 0, sizeof(*work));
    memcpy(work, &bench_block, min_size);
    work->mandatory = true;
    work->pool = pools[0];
    gettimeofday(&(work->tv_getwork), NULL);
    memcpy(&(work->tv_getwork_reply), &(work->tv_getwork), sizeof(struct timeval));
    work->getwork_mode = GETWORK_MODE_BENCHMARK;
    calc_diff(work, 0.0);
}

#ifdef HAVE_CURSES
static void disable_curses(void)
{
    if (curses_active_locked())
    {
        curses_active = false;
        leaveok(logwin, false);
        leaveok(statuswin, false);
        leaveok(mainwin, false);
        nocbreak();
        echo();
        delwin(logwin);
        delwin(statuswin);
        delwin(mainwin);
        endwin();
#ifdef WIN32
        // Move the cursor to after curses output.
        HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        COORD coord;

        if (GetConsoleScreenBufferInfo(hout, &csbi))
        {
            coord.X = 0;
            coord.Y = csbi.dwSize.Y - 1;
            SetConsoleCursorPosition(hout, coord);
        }
#endif
        unlock_curses();
    }
}
#endif

static void __kill_work(void)
{
    struct thr_info* thr;
    int i;

    if (!successful_connect)
        return;

    applog(LOG_INFO, "Received kill message");

    applog(LOG_DEBUG, "Killing off watchpool thread");
    /* Kill the watchpool thread */
    thr = &control_thr[watchpool_thr_id];
    thr_info_cancel(thr);

    applog(LOG_DEBUG, "Killing off watchdog thread");
    /* Kill the watchdog thread */
    thr = &control_thr[watchdog_thr_id];
    thr_info_cancel(thr);

    applog(LOG_DEBUG, "Stopping mining threads");
    /* Stop the mining threads*/
    for (i = 0; i < mining_threads; i++)
    {
        thr = get_thread(i);
        thr_info_freeze(thr);
        thr->pause = true;
    }

    nmsleep(1000);

    applog(LOG_DEBUG, "Killing off mining threads");
    /* Kill the mining threads*/
    for (i = 0; i < mining_threads; i++)
    {
        thr = get_thread(i);
        thr_info_cancel(thr);
    }

    applog(LOG_DEBUG, "Killing off stage thread");
    /* Stop the others */
    thr = &control_thr[stage_thr_id];
    thr_info_cancel(thr);

    applog(LOG_DEBUG, "Killing off API thread");
    thr = &control_thr[api_thr_id];
    thr_info_cancel(thr);
}

/* This should be the common exit path */
void kill_work(void)
{
    __kill_work();

    nxquit(0, "Shutdown signal received.");
}

static char** initial_args;

static void clean_up(void);

void app_restart(void)
{
    applog(LOG_WARNING, "Attempting to restart %s", packagename);

    __kill_work();
    clean_up();

#if defined(unix)
    if (forkpid > 0)
    {
        kill(forkpid, SIGTERM);
        forkpid = 0;
    }
#endif

    execv(initial_args[0], initial_args);
    applog(LOG_WARNING, "Failed to restart application");
}

static void sighandler(int __maybe_unused sig)
{
    /* Restore signal handlers so we can still quit if kill_work fails */
    sigaction(SIGTERM, &termhandler, NULL);
    sigaction(SIGINT, &inthandler, NULL);
    kill_work();
}

/* Called with pool_lock held. Recruit an extra curl if none are available for
 * this pool. */
static void recruit_curl(struct pool* pool)
{
    struct curl_ent* ce = calloc(sizeof(struct curl_ent), 1);

    if (unlikely(!ce))
        nxquit(1, "Failed to calloc in recruit_curl");

    ce->curl = curl_easy_init();
    if (unlikely(!ce->curl))
        nxquit(1, "Failed to init in recruit_curl");

    list_add(&ce->node, &pool->curlring);
    pool->curls++;
    applog(LOG_DEBUG, "Recruited curl %d for pool %d", pool->curls, pool->pool_no);
}

/* Grab an available curl if there is one. If not, then recruit extra curls
 * unless we are in a submit_fail situation, or we have opt_delaynet enabled
 * and there are already 5 curls in circulation. Limit total number to the
 * number of mining threads per pool as well to prevent blasting a pool during
 * network delays/outages. */
static struct curl_ent* pop_curl_entry(struct pool* pool)
{
    int curl_limit = opt_delaynet ? 5 : (mining_threads + opt_queue) * 2;
    struct curl_ent* ce;

    mutex_lock(&pool->pool_lock);
retry:
    if (!pool->curls)
        recruit_curl(pool);
    else if (list_empty(&pool->curlring))
    {
        if (pool->curls >= curl_limit)
        {
            pthread_cond_wait(&pool->cr_cond, &pool->pool_lock);
            goto retry;
        }
        else
            recruit_curl(pool);
    }
    ce = list_entry(pool->curlring.next, struct curl_ent, node);
    list_del(&ce->node);
    mutex_unlock(&pool->pool_lock);

    return ce;
}

static void push_curl_entry(struct curl_ent* ce, struct pool* pool)
{
    mutex_lock(&pool->pool_lock);
    list_add_tail(&ce->node, &pool->curlring);
    gettimeofday(&ce->tv, NULL);
    pthread_cond_broadcast(&pool->cr_cond);
    mutex_unlock(&pool->pool_lock);
}

static bool stale_work(struct work* work, bool share);

/* Duplicates any dynamically allocated arrays within the work struct to
 * prevent a copied work struct from freeing ram belonging to another struct */
void __copy_work(struct work* work, struct work* base_work)
{
    int id = work->id;

    clean_work(work);
    memcpy(work, base_work, sizeof(struct work));
    /* Keep the unique new id assigned during make_work to prevent copied
     * work from having the same id. */
    work->id = id;
    if (base_work->job_id)
    {
        work->job_id = strdup(base_work->job_id);
    }
    if (base_work->start_nonce)
    {
        memcpy(work->start_nonce, base_work->start_nonce, 16);
    }
    if (base_work->nonce)
    {
        memcpy(work->nonce, base_work->nonce, 16);
    }
    if (base_work->ntime)
    {
		work->ntime = strdup(base_work->ntime);
    }
    if (base_work->headerCommitment)
    {
        memcpy(work->headerCommitment, base_work->headerCommitment, 32);
    }
}

/* Generates a copy of an existing work struct, creating fresh heap allocations
 * for all dynamically allocated arrays within the struct */
struct work* copy_work(struct work* base_work)
{
    struct work* work = make_work();

    __copy_work(work, base_work);

    return work;
}

static struct work* make_clone(struct work* work)
{
    struct work* work_clone = copy_work(work);

    work_clone->clone = true;
    gettimeofday((struct timeval*)&(work_clone->tv_cloned), NULL);
    work_clone->mandatory = false;
    /* Make cloned work appear slightly older to bias towards keeping the
     * master work item which can be further rolled */
    work_clone->tv_staged.tv_sec -= 1;

    return work_clone;
}

static void stage_work(struct work* work);

static void pool_died(struct pool* pool)
{
    if (!pool_tset(pool, &pool->idle))
    {
        gettimeofday(&pool->tv_idle, NULL);
        if (pool == current_pool())
        {
            applog(LOG_WARNING, "Pool %d %s not responding!", pool->pool_no, pool->rpc_url);
            switch_pools(NULL);
        }
        else
            applog(LOG_INFO, "Pool %d %s failed to return work", pool->pool_no, pool->rpc_url);
    }
}

static bool stale_work(struct work* work, bool share)
{
    struct timeval now;
    time_t work_expiry;
    struct pool* pool;
    int getwork_delay;

    if (opt_benchmark)
        return false;

    if (work->work_block != work_block)
    {
        applog(LOG_DEBUG, "Work stale due to block mismatch");
        return true;
    }

    /* Technically the rolltime should be correct but some pools
     * advertise a broken expire= that is lower than a meaningful
     * scantime */
    if (work->rolltime > opt_scantime)
        work_expiry = work->rolltime;
    else
        work_expiry = opt_expiry;

    pool = work->pool;

    /* Factor in the average getwork delay of this pool, rounding it up to
     * the nearest second */
    getwork_delay = pool->cgminer_pool_stats.getwork_wait_rolling * 5 + 1;
    work_expiry -= getwork_delay;
    if (unlikely(work_expiry < 5))
        work_expiry = 5;

    gettimeofday(&now, NULL);
    if ((now.tv_sec - work->tv_staged.tv_sec) >= work_expiry)
    {
        applog(LOG_DEBUG, "Work stale due to expiry");
        return true;
    }

    if (opt_fail_only && !share && pool != current_pool() && !work->mandatory && pool_strategy != POOL_LOADBALANCE &&
        pool_strategy != POOL_BALANCE)
    {
        applog(LOG_DEBUG, "Work stale due to fail only pool mismatch");
        return true;
    }

    pool = work->pool;

    if (!share && pool->has_stratum)
    {
        bool same_job;

        if (!pool->stratum_active || !pool->stratum_notify)
        {
            applog(LOG_DEBUG, "Work stale due to stratum inactive");
            return true;
        }

        same_job = true;
        cg_rlock(&pool->data_lock);
        if (strcmp(work->job_id, pool->swork.job_id))
            same_job = false;
        cg_runlock(&pool->data_lock);
        if (!same_job)
        {
            applog(LOG_DEBUG, "Work stale due to stratum job_id mismatch");
            return true;
        }
    }

    /* Factor in the average getwork delay of this pool, rounding it up to
     * the nearest second */
    getwork_delay = pool->cgminer_pool_stats.getwork_wait_rolling * 5 + 1;
    work_expiry -= getwork_delay;
    if (unlikely(work_expiry < 5))
        work_expiry = 5;

    gettimeofday(&now, NULL);
    if ((now.tv_sec - work->tv_staged.tv_sec) >= work_expiry)
    {
        applog(LOG_DEBUG, "Work stale due to expiry");
        return true;
    }

    if (opt_fail_only && !share && pool != current_pool() && !work->mandatory && pool_strategy != POOL_LOADBALANCE &&
        pool_strategy != POOL_BALANCE)
    {
        applog(LOG_DEBUG, "Work stale due to fail only pool mismatch");
        return true;
    }

    return false;
}

static bool cnx_needed(struct pool* pool);

static void* submit_work_thread(void* userdata)
{
    struct work* work = (struct work*)userdata;
    struct pool* pool = work->pool;
    bool resubmit = false;
    struct curl_ent* ce;

    pthread_detach(pthread_self());

    RenameThread("submit_work");

    applog(LOG_DEBUG, "Creating extra submit work thread");

    if (stale_work(work, true))
    {
        if (opt_submit_stale)
        {
            applog(LOG_NOTICE, "Pool %d stale share detected, submitting as user requested", pool->pool_no);
        }
        else if (pool->submit_old)
        {
            applog(LOG_NOTICE, "Pool %d stale share detected, submitting as pool requested", pool->pool_no);
        }
        else
        {
            applog(LOG_NOTICE, "Pool %d stale share detected, discarding", pool->pool_no);
            sharelog("discard", work);

            mutex_lock(&stats_lock);
            total_stale++;
            pool->stale_shares++;
            total_diff_stale += work->work_difficulty;
            pool->diff_stale += work->work_difficulty;
            mutex_unlock(&stats_lock);
            goto out;
        }
        work->stale = true;
    }

    if (work->stratum)
    {
        struct stratum_share* sshare = calloc(sizeof(struct stratum_share), 1);
        bool submitted = false;
        char* noncehex;
        char s[1024];

        sshare->sshare_time = time(NULL);
        /* This work item is freed in parse_stratum_response */
        sshare->work = work;
        noncehex = bin2hex(work->nonce, 16);
        char* headerCommitmentHex = bin2hex(work->headerCommitment, 32);
        memset(s, 0, 1024);

        mutex_lock(&sshare_lock);
        /* Give the stratum share a unique id */
        sshare->id = swork_id++;
        mutex_unlock(&sshare_lock);

        sprintf(s, "{\"params\": [\"%s\", \"%s\", \"%lu\", \"%s\", \"%u\", \"%s\", \"%s\" ], \"id\": %d, \"method\": \"mining.submit\"}",
            pool->rpc_user, work->job_id, work->candidateId, headerCommitmentHex, work->nBits, noncehex, work->ntime, sshare->id);
        free(headerCommitmentHex);

        applog(LOG_INFO, "Submitting share with nonce %s, difficulty %f, to pool %d", noncehex, work->work_difficulty, pool->pool_no);
        free(noncehex);

        /* Try resubmitting for up to 2 minutes if we fail to submit
         * once and the stratum pool nonce1 still matches suggesting
         * we may be able to resume. */
        while (time(NULL) < sshare->sshare_time + 120)
        {
            bool sessionid_match;

            if (likely(stratum_send(pool, s, strlen(s))))
            {
                if (pool_tclear(pool, &pool->submit_fail))
                {
                    applog(LOG_WARNING, "Pool %d communication resumed, submitting work", pool->pool_no);
                }
                mutex_lock(&sshare_lock);
                HASH_ADD_INT(stratum_shares, id, sshare);
                pool->sshares++;
                mutex_unlock(&sshare_lock);
                applog(LOG_DEBUG, "Successfully submitted, adding to stratum_shares db");
                submitted = true;
                break;
            }
            if (!pool_tset(pool, &pool->submit_fail) && cnx_needed(pool))
            {
                applog(LOG_WARNING, "Pool %d stratum share submission failure", pool->pool_no);
                total_ro++;
                pool->remotefail_occasions++;
            }

            cg_rlock(&pool->data_lock);
            sessionid_match = work->nonce1 == pool->nonce1;
            cg_runlock(&pool->data_lock);

            if (!sessionid_match)
            {
                applog(LOG_DEBUG, "No matching session id for resubmitting stratum share");
                break;
            }
            /* Retry every 5 seconds */
            sleep(5);
        }

        if (unlikely(!submitted))
        {
            applog(LOG_DEBUG, "Failed to submit stratum share, discarding");
            free_work(work);
            free(sshare);
            pool->stale_shares++;
            total_stale++;
        }
    }
out:
    return NULL;
}

void discard_work(struct work* work)
{
    if (!work->clone && !work->rolls && !work->mined)
    {
        if (work->pool)
            work->pool->discarded_work++;
        total_discarded++;
        applog(LOG_DEBUG, "Discarded work");
    }
    else
        applog(LOG_DEBUG, "Discarded cloned or rolled work");
    free_work(work);
}

static bool cnx_needed(struct pool* pool);

/* Find the pool that currently has the highest priority */
static struct pool* priority_pool(int choice)
{
    struct pool* ret = NULL;
    int i;

    for (i = 0; i < total_pools; i++)
    {
        struct pool* pool = pools[i];

        if (pool->prio == choice)
        {
            ret = pool;
            break;
        }
    }

    if (unlikely(!ret))
    {
        applog(LOG_ERR, "WTF No pool %d found!", choice);
        return pools[choice];
    }
    return ret;
}

static void clear_pool_work(struct pool* pool);

/* Specifies whether we can switch to this pool or not. */
static bool pool_unusable(struct pool* pool)
{
    if (pool->idle)
        return true;
    if (pool->enabled != POOL_ENABLED)
        return true;
    return false;
}

void switch_pools(struct pool* selected)
{
    struct pool *pool, *last_pool;
    int i, pool_no, next_pool;

    cg_wlock(&control_lock);
    last_pool = currentpool;
    pool_no = currentpool->pool_no;

    /* Switch selected to pool number 0 and move the rest down */
    if (selected)
    {
        if (selected->prio != 0)
        {
            for (i = 0; i < total_pools; i++)
            {
                pool = pools[i];
                if (pool->prio < selected->prio)
                    pool->prio++;
            }
            selected->prio = 0;
        }
    }

    switch (pool_strategy)
    {
    /* Both of these set to the master pool */
    case POOL_BALANCE:
    case POOL_FAILOVER:
    case POOL_LOADBALANCE:
        for (i = 0; i < total_pools; i++)
        {
            pool = priority_pool(i);
            if (pool_unusable(pool))
                continue;
            pool_no = pool->pool_no;
            break;
        }
        break;
    /* Both of these simply increment and cycle */
    case POOL_ROUNDROBIN:
    case POOL_ROTATE:
        if (selected && !selected->idle)
        {
            pool_no = selected->pool_no;
            break;
        }
        next_pool = pool_no;
        /* Select the next alive pool */
        for (i = 1; i < total_pools; i++)
        {
            next_pool++;
            if (next_pool >= total_pools)
                next_pool = 0;
            pool = pools[next_pool];
            if (pool_unusable(pool))
                continue;
            pool_no = next_pool;
            break;
        }
        break;
    default:
        break;
    }

    currentpool = pools[pool_no];
    pool = currentpool;
    cg_wunlock(&control_lock);

    /* Set the lagging flag to avoid pool not providing work fast enough
     * messages in failover only mode since  we have to get all fresh work
     * as in restart_threads */
    if (opt_fail_only)
        pool_tset(pool, &pool->lagging);

    if (pool != last_pool && pool_strategy != POOL_LOADBALANCE && pool_strategy != POOL_BALANCE)
    {
        applog(LOG_WARNING, "Switching to pool %d %s", pool->pool_no, pool->rpc_url);
        if (opt_fail_only)
        {
            clear_pool_work(last_pool);
        }
    }

    mutex_lock(&lp_lock);
    pthread_cond_broadcast(&lp_cond);
    mutex_unlock(&lp_lock);
}

static void wake_gws(void)
{
    mutex_lock(stgd_lock);
    pthread_cond_signal(&gws_cond);
    mutex_unlock(stgd_lock);
}

static void discard_stale(void)
{
    struct work *work, *tmp;
    int stale = 0;

    mutex_lock(stgd_lock);
    HASH_ITER(hh, staged_work, work, tmp)
    {
        if (stale_work(work, false))
        {
            HASH_DEL(staged_work, work);
            discard_work(work);
            stale++;
        }
    }
    pthread_cond_signal(&gws_cond);
    mutex_unlock(stgd_lock);

    if (stale)
        applog(LOG_DEBUG, "Discarded %d stales that didn't match current hash", stale);
}

/* A generic wait function for threads that poll that will wait a specified
 * time tdiff waiting on the pthread conditional that is broadcast when a
 * work restart is required. Returns the value of pthread_cond_timedwait
 * which is zero if the condition was met or ETIMEDOUT if not.
 */
int restart_wait(unsigned int mstime)
{
    struct timeval now, then, tdiff;
    struct timespec abstime;
    int rc;

    tdiff.tv_sec = mstime / 1000;
    tdiff.tv_usec = mstime * 1000 - (tdiff.tv_sec * 1000000);
    gettimeofday(&now, NULL);
    timeradd(&now, &tdiff, &then);
    abstime.tv_sec = then.tv_sec;
    abstime.tv_nsec = then.tv_usec * 1000;

    mutex_lock(&restart_lock);
    rc = pthread_cond_timedwait(&restart_cond, &restart_lock, &abstime);
    mutex_unlock(&restart_lock);

    return rc;
}

static void restart_threads(void)
{
    struct pool* cp = current_pool();
    int i;

    /* Artificially set the lagging flag to avoid pool not providing work
     * fast enough  messages after every long poll */
    pool_tset(cp, &cp->lagging);

    /* Discard staged work that is now stale */
    discard_stale();

    rd_lock(&mining_thr_lock);
    for (i = 0; i < mining_threads; i++)
    {
        mining_thr[i]->work_restart = true;
    }
    rd_unlock(&mining_thr_lock);

    mutex_lock(&restart_lock);
    pthread_cond_broadcast(&restart_cond);
    mutex_unlock(&restart_lock);
}

static void set_headerCommitment(char* hexstr, unsigned char* hash)
{
    unsigned char hash_swap[32];
    unsigned char block_hash_swap[32];

    memcpy(current_block, hexstr, 65);
    swap256(hash_swap, hash);
    swap256(block_hash_swap, hash);

    cg_wlock(&ch_lock);
    gettimeofday(&block_timeval, NULL);
    free(current_hash);
    current_hash = bin2hex(hash_swap, 8);
    free(current_fullhash);
    current_fullhash = bin2hex(block_hash_swap, 32);
    get_timestamp(blocktime, &block_timeval);
    applog(LOG_INFO, "New block: %s... diff %s", current_hash, block_diff);
    cg_wunlock(&ch_lock);
}

/* Search to see if this string is from a block that has been seen before */
static bool block_exists(char* hexstr)
{
    struct block* s;

    rd_lock(&blk_lock);
    HASH_FIND_STR(blocks, hexstr, s);
    rd_unlock(&blk_lock);
    if (s)
        return true;
    return false;
}

static int block_sort(struct block* blocka, struct block* blockb)
{
    return blocka->block_no - blockb->block_no;
}

static void set_blockdiff(const struct work *work)
{
    current_block_diff = nbits_to_difficulty(&work->pool->swork.nBits);
    suffix_string_double(current_block_diff, block_diff, 6);
    current_share_diff = work->work_difficulty;
    suffix_string_double(current_share_diff, share_diff, 6);
}

static bool test_work_current(struct work* work)
{
    bool ret = true;

    if (work->mandatory)
        return ret;

    /* Hack to work around dud work sneaking into test */
    // use headercommitment rather than block hash
    uint8_t* hexstr = bin2hex(work->headerCommitment, 32);
    if (!strncmp(hexstr, "00000000000000000000000000000000", 32))
    	goto out_free;

    /* Search to see if this block exists yet and if not, consider it a
     * new block and set the current block details to this one */
    if (!block_exists(hexstr))
    {
        struct block* s = calloc(sizeof(struct block), 1);
        int deleted_block = 0;
        ret = false;

        if (unlikely(!s))
        {
            nxquit(1, "test_work_current OOM");
        }
        memcpy(s->commitment_hex, hexstr, 65);
        s->block_no = new_blocks++;
        wr_lock(&blk_lock);
        /* Only keep the last hour's worth of blocks in memory since
         * work from blocks before this is virtually impossible and we
         * want to prevent memory usage from continually rising */
        if (HASH_COUNT(blocks) > 6)
        {
            struct block* oldblock;

            HASH_SORT(blocks, block_sort);
            oldblock = blocks;
            deleted_block = oldblock->block_no;
            HASH_DEL(blocks, oldblock);
            free(oldblock);
        }
        HASH_ADD_STR(blocks, commitment_hex, s);
        set_blockdiff(work);
        wr_unlock(&blk_lock);
        if (deleted_block)
            applog(LOG_DEBUG, "Deleted block %d from database", deleted_block);
        set_headerCommitment(hexstr, work->headerCommitment);
        if (unlikely(new_blocks == 1))
        {
            goto out_free;
        }
        free(hexstr);

        work->work_block = ++work_block;
        restart_threads();
    }
out_free:
    return ret;
}

static int tv_sort(struct work* worka, struct work* workb)
{
    return worka->tv_staged.tv_sec - workb->tv_staged.tv_sec;
}

static bool work_rollable(struct work* work)
{
    return (!work->clone && work->rolltime);
}

static bool hash_push(struct work* work)
{
    bool rc = true;

    mutex_lock(stgd_lock);
    if (work_rollable(work))
        staged_rollable++;
    if (likely(!getq->frozen))
    {
        HASH_ADD_INT(staged_work, id, work);
        HASH_SORT(staged_work, tv_sort);
    }
    else
        rc = false;
    pthread_cond_broadcast(&getq->cond);
    mutex_unlock(stgd_lock);

    return rc;
}

static void* stage_thread(void* userdata)
{
    struct thr_info* mythr = userdata;
    bool ok = true;

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    RenameThread("stage");

    while (ok)
    {
        struct work* work = NULL;

        applog(LOG_DEBUG, "Popping work to stage thread");

        work = tq_pop(mythr->q, NULL);
        if (unlikely(!work))
        {
            applog(LOG_ERR, "Failed to tq_pop in stage_thread");
            ok = false;
            break;
        }
        work->work_block = work_block;

        test_work_current(work);

        applog(LOG_DEBUG, "Pushing work to getwork queue");

        if (unlikely(!hash_push(work)))
        {
            applog(LOG_WARNING, "Failed to hash_push in stage_thread");
            continue;
        }
    }

    tq_freeze(mythr->q);
    return NULL;
}

static void stage_work(struct work* work)
{
    work->work_block = work_block;
    test_work_current(work);
    applog(LOG_DEBUG, "Pushing work from pool %d to hash queue", work->pool->pool_no);
    hash_push(work);
}

#ifdef HAVE_CURSES
int curses_int(const char* query)
{
    int ret;
    char* cvar;

    cvar = curses_input(query);
    ret = atoi(cvar);
    free(cvar);
    return ret;
}
#endif

#ifdef HAVE_CURSES
static bool input_pool(bool live);
#endif

#ifdef HAVE_CURSES
static void display_pool_summary(struct pool* pool)
{
    double efficiency = 0.0;

    if (curses_active_locked())
    {
        wlog("Pool: %s\n", pool->rpc_url);
        if (pool->solved)
            wlog("SOLVED %d BLOCK%s!\n", pool->solved, pool->solved > 1 ? "S" : "");
        wlog("%s own long-poll support\n", pool->hdr_path ? "Has" : "Does not have");
        wlog(" Queued work requests: %d\n", pool->getwork_requested);
        wlog(" Share submissions: %d\n", pool->accepted + pool->rejected);
        wlog(" Accepted shares: %d\n", pool->accepted);
        wlog(" Rejected shares: %d\n", pool->rejected);
        wlog(" Accepted difficulty shares: %1.f\n", pool->diff_accepted);
        wlog(" Rejected difficulty shares: %1.f\n", pool->diff_rejected);
        if (pool->accepted || pool->rejected)
            wlog(" Reject ratio: %.1f%%\n", (double)(pool->rejected * 100) / (double)(pool->accepted + pool->rejected));
        efficiency = pool->getwork_requested ? pool->accepted * 100.0 / pool->getwork_requested : 0.0;
        wlog(" Efficiency (accepted / queued): %.0f%%\n", efficiency);

        wlog(" Discarded work due to new blocks: %d\n", pool->discarded_work);
        wlog(" Stale submissions discarded due to new blocks: %d\n", pool->stale_shares);
        wlog(" Unable to get work from server occasions: %d\n", pool->getfail_occasions);
        wlog(" Submitting work remotely delay occasions: %d\n\n", pool->remotefail_occasions);
        unlock_curses();
    }
}
#endif

/* We can't remove the memory used for this struct pool because there may
 * still be work referencing it. We just remove it from the pools list */
void remove_pool(struct pool* pool)
{
    int i, last_pool = total_pools - 1;
    struct pool* other;

    /* Boost priority of any lower prio than this one */
    for (i = 0; i < total_pools; i++)
    {
        other = pools[i];
        if (other->prio > pool->prio)
            other->prio--;
    }

    if (pool->pool_no < last_pool)
    {
        /* Swap the last pool for this one */
        (pools[last_pool])->pool_no = pool->pool_no;
        pools[pool->pool_no] = pools[last_pool];
    }
    /* Give it an invalid number */
    pool->pool_no = total_pools;
    pool->removed = true;
    total_pools--;
}

/* add a mutex if this needs to be thread safe in the future */
static struct JE
{
    char* buf;
    struct JE* next;
}* jedata = NULL;

static void json_escape_free()
{
    struct JE* jeptr = jedata;
    struct JE* jenext;

    jedata = NULL;

    while (jeptr)
    {
        jenext = jeptr->next;
        free(jeptr->buf);
        free(jeptr);
        jeptr = jenext;
    }
}

static char* json_escape(char* str)
{
    struct JE* jeptr;
    char *buf, *ptr;

    /* 2x is the max, may as well just allocate that */
    ptr = buf = malloc(strlen(str) * 2 + 1);

    jeptr = malloc(sizeof(*jeptr));

    jeptr->buf = buf;
    jeptr->next = jedata;
    jedata = jeptr;

    while (*str)
    {
        if (*str == '\\' || *str == '"')
            *(ptr++) = '\\';

        *(ptr++) = *(str++);
    }

    *ptr = '\0';

    return buf;
}

void write_config(FILE* fcfg)
{
    int i;

    /* Write pool values */
    fputs("{\n\"pools\" : [", fcfg);
    for (i = 0; i < total_pools; i++)
    {
        fprintf(fcfg, "%s\n\t{\n\t\t\"url\" : \"%s%s%s%s\",", i > 0 ? "," : "",
            pools[i]->rpc_proxy ? json_escape((char*)proxytype(pools[i]->rpc_proxytype)) : "",
            pools[i]->rpc_proxy ? json_escape(pools[i]->rpc_proxy) : "", pools[i]->rpc_proxy ? "|" : "",
            json_escape(pools[i]->rpc_url));
        fprintf(fcfg, "\n\t\t\"user\" : \"%s\",", json_escape(pools[i]->rpc_user));
        fprintf(fcfg, "\n\t\t\"pass\" : \"%s\"\n\t}", json_escape(pools[i]->rpc_pass));
    }
    fputs("\n]\n", fcfg);

#ifdef HAVE_OPENCL
    if (nDevs)
    {
        /* Write GPU device values */
        fputs(",\n\"intensity\" : \"", fcfg);
        for (i = 0; i < nDevs; i++)
            fprintf(fcfg, gpus[i].dynamic ? "%sd" : "%s%d", i > 0 ? "," : "", gpus[i].intensity);
        fputs("\",\n\"vectors\" : \"", fcfg);
        for (i = 0; i < nDevs; i++)
            fprintf(fcfg, "%s%d", i > 0 ? "," : "", gpus[i].vwidth);
        fputs("\",\n\"worksize\" : \"", fcfg);
        for (i = 0; i < nDevs; i++)
            fprintf(fcfg, "%s%d", i > 0 ? "," : "", (int)gpus[i].work_size);
        fputs("\",\n\"kernel\" : \"", fcfg);
        for (i = 0; i < nDevs; i++)
        {
            fprintf(fcfg, "%s", i > 0 ? "," : "");
            switch (gpus[i].kernel)
            {
            case KL_NONE: // Shouldn't happen
                break;
            case KL_DIABLO:
                fprintf(fcfg, "diablo");
                break;
            }
        }
#ifdef HAVE_ADL
        fputs("\",\n\"gpu-engine\" : \"", fcfg);
        for (i = 0; i < nDevs; i++)
            fprintf(fcfg, "%s%d-%d", i > 0 ? "," : "", gpus[i].min_engine, gpus[i].gpu_engine);
        fputs("\",\n\"gpu-fan\" : \"", fcfg);
        for (i = 0; i < nDevs; i++)
            fprintf(fcfg, "%s%d-%d", i > 0 ? "," : "", gpus[i].min_fan, gpus[i].gpu_fan);
        fputs("\",\n\"gpu-memclock\" : \"", fcfg);
        for (i = 0; i < nDevs; i++)
            fprintf(fcfg, "%s%d", i > 0 ? "," : "", gpus[i].gpu_memclock);
        fputs("\",\n\"gpu-memdiff\" : \"", fcfg);
        for (i = 0; i < nDevs; i++)
            fprintf(fcfg, "%s%d", i > 0 ? "," : "", gpus[i].gpu_memdiff);
        fputs("\",\n\"gpu-powertune\" : \"", fcfg);
        for (i = 0; i < nDevs; i++)
            fprintf(fcfg, "%s%d", i > 0 ? "," : "", gpus[i].gpu_powertune);
        fputs("\",\n\"gpu-vddc\" : \"", fcfg);
        for (i = 0; i < nDevs; i++)
            fprintf(fcfg, "%s%1.3f", i > 0 ? "," : "", gpus[i].gpu_vddc);
        fputs("\",\n\"temp-cutoff\" : \"", fcfg);
        for (i = 0; i < nDevs; i++)
            fprintf(fcfg, "%s%d", i > 0 ? "," : "", gpus[i].cutofftemp);
        fputs("\",\n\"temp-overheat\" : \"", fcfg);
        for (i = 0; i < nDevs; i++)
            fprintf(fcfg, "%s%d", i > 0 ? "," : "", gpus[i].adl.overtemp);
        fputs("\",\n\"temp-target\" : \"", fcfg);
        for (i = 0; i < nDevs; i++)
            fprintf(fcfg, "%s%d", i > 0 ? "," : "", gpus[i].adl.targettemp);
#endif
        fputs("\"", fcfg);
    }
#endif
#ifdef HAVE_ADL
    if (opt_reorder)
        fprintf(fcfg, ",\n\"gpu-reorder\" : true");
#endif
#ifdef WANT_CPUMINE
    fprintf(fcfg, ",\n\"algo\" : \"%s\"", algo_names[opt_algo]);
#endif

    /* Simple bool and int options */
    struct opt_table* opt;
    for (opt = opt_config_table; opt->type != OPT_END; opt++)
    {
        char *p, *name = strdup(opt->names);
        for (p = strtok(name, "|"); p; p = strtok(NULL, "|"))
        {
            if (p[1] != '-')
                continue;
            if (opt->type & OPT_NOARG &&
                ((void*)opt->cb == (void*)opt_set_bool || (void*)opt->cb == (void*)opt_set_invbool) &&
                (*(bool*)opt->u.arg == ((void*)opt->cb == (void*)opt_set_bool)))
                fprintf(fcfg, ",\n\"%s\" : true", p + 2);

            if (opt->type & OPT_HASARG &&
                ((void*)opt->cb_arg == (void*)set_int_0_to_9999 || (void*)opt->cb_arg == (void*)set_int_1_to_65535 ||
                    (void*)opt->cb_arg == (void*)set_int_0_to_10 || (void*)opt->cb_arg == (void*)set_int_1_to_10) &&
                opt->desc != opt_hidden)
                fprintf(fcfg, ",\n\"%s\" : \"%d\"", p + 2, *(int*)opt->u.arg);
        }
    }

    /* Special case options */
    fprintf(fcfg, ",\n\"shares\" : \"%d\"", opt_shares);
    if (pool_strategy == POOL_BALANCE)
        fputs(",\n\"balance\" : true", fcfg);
    if (pool_strategy == POOL_LOADBALANCE)
        fputs(",\n\"load-balance\" : true", fcfg);
    if (pool_strategy == POOL_ROUNDROBIN)
        fputs(",\n\"round-robin\" : true", fcfg);
    if (pool_strategy == POOL_ROTATE)
        fprintf(fcfg, ",\n\"rotate\" : \"%d\"", opt_rotate_period);
#if defined(unix)
    if (opt_stderr_cmd && *opt_stderr_cmd)
        fprintf(fcfg, ",\n\"monitor\" : \"%s\"", json_escape(opt_stderr_cmd));
#endif // defined(unix)
    if (opt_kernel_path && *opt_kernel_path)
    {
        char* kpath = strdup(opt_kernel_path);
        if (kpath[strlen(kpath) - 1] == '/')
            kpath[strlen(kpath) - 1] = 0;
        fprintf(fcfg, ",\n\"kernel-path\" : \"%s\"", json_escape(kpath));
    }
    if (schedstart.enable)
        fprintf(fcfg, ",\n\"sched-time\" : \"%d:%d\"", schedstart.tm.tm_hour, schedstart.tm.tm_min);
    if (schedstop.enable)
        fprintf(fcfg, ",\n\"stop-time\" : \"%d:%d\"", schedstop.tm.tm_hour, schedstop.tm.tm_min);
    if (opt_socks_proxy && *opt_socks_proxy)
        fprintf(fcfg, ",\n\"socks-proxy\" : \"%s\"", json_escape(opt_socks_proxy));
#ifdef HAVE_OPENCL
    for (i = 0; i < nDevs; i++)
        if (gpus[i].deven == DEV_DISABLED)
            break;
    if (i < nDevs)
        for (i = 0; i < nDevs; i++)
            if (gpus[i].deven != DEV_DISABLED)
                fprintf(fcfg, ",\n\"device\" : \"%d\"", i);
#endif
    if (opt_api_allow)
        fprintf(fcfg, ",\n\"api-allow\" : \"%s\"", json_escape(opt_api_allow));
    if (strcmp(opt_api_description, PACKAGE_STRING) != 0)
        fprintf(fcfg, ",\n\"api-description\" : \"%s\"", json_escape(opt_api_description));
    if (opt_api_groups)
        fprintf(fcfg, ",\n\"api-groups\" : \"%s\"", json_escape(opt_api_groups));
    fputs("\n}\n", fcfg);

    json_escape_free();
}

void zero_bestshare(void)
{
    int i;

    best_diff = 0;
    memset(best_share, 0, 8);
    suffix_string_double(best_diff, best_share, 0);

    for (i = 0; i < total_pools; i++)
    {
        struct pool* pool = pools[i];
        pool->best_diff = 0;
    }
}

void zero_stats(void)
{
    int i;

    gettimeofday(&total_tv_start, NULL);
    total_mhashes_done = 0;
    total_getworks = 0;
    total_accepted = 0;
    total_rejected = 0;
    hw_errors = 0;
    total_stale = 0;
    total_discarded = 0;
    local_work = 0;
    total_go = 0;
    total_ro = 0;
    total_secs = 1.0;
    total_diff1 = 0;
    found_blocks = 0;
    total_diff_accepted = 0;
    total_diff_rejected = 0;
    total_diff_stale = 0;

    for (i = 0; i < total_pools; i++)
    {
        struct pool* pool = pools[i];

        pool->getwork_requested = 0;
        pool->accepted = 0;
        pool->rejected = 0;
        pool->stale_shares = 0;
        pool->discarded_work = 0;
        pool->getfail_occasions = 0;
        pool->remotefail_occasions = 0;
        pool->last_share_time = 0;
        pool->diff1 = 0;
        pool->diff_accepted = 0;
        pool->diff_rejected = 0;
        pool->diff_stale = 0;
        pool->last_share_diff = 0;
    }

    zero_bestshare();

    for (i = 0; i < total_devices; ++i)
    {
        struct cgpu_info* cgpu = get_devices(i);

        mutex_lock(&hash_lock);
        cgpu->total_mhashes = 0;
        cgpu->accepted = 0;
        cgpu->rejected = 0;
        cgpu->hw_errors = 0;
        cgpu->utility = 0.0;
        cgpu->last_share_pool_time = 0;
        cgpu->diff1 = 0;
        cgpu->diff_accepted = 0;
        cgpu->diff_rejected = 0;
        cgpu->last_share_diff = 0;
        mutex_unlock(&hash_lock);
    }
}

#ifdef HAVE_CURSES
static void display_pools(void)
{
    struct pool* pool;
    int selected, i;
    char input;

    opt_loginput = true;
    immedok(logwin, true);
    clear_logwin();
updated:
    for (i = 0; i < total_pools; i++)
    {
        pool = pools[i];

        if (pool == current_pool())
            wattron(logwin, A_BOLD);
        if (pool->enabled != POOL_ENABLED)
            wattron(logwin, A_DIM);
        wlogprint("%d: ", pool->pool_no);
        switch (pool->enabled)
        {
        case POOL_ENABLED:
            wlogprint("Enabled ");
            break;
        case POOL_DISABLED:
            wlogprint("Disabled ");
            break;
        case POOL_REJECTING:
            wlogprint("Rejecting ");
            break;
        }
        wlogprint(
            "%s Priority %d: %s  User:%s\n", pool->idle ? "Dead" : "Alive", pool->prio, pool->rpc_url, pool->rpc_user);
        wattroff(logwin, A_BOLD | A_DIM);
    }
retry:
    wlogprint("\nCurrent pool management strategy: %s\n", strategies[pool_strategy].s);
    if (pool_strategy == POOL_ROTATE)
        wlogprint("Set to rotate every %d minutes\n", opt_rotate_period);
    wlogprint("[F]ailover only %s\n", opt_fail_only ? "enabled" : "disabled");
    wlogprint("[A]dd pool [R]emove pool [D]isable pool [E]nable pool\n");
    wlogprint("[C]hange management strategy [S]witch pool [I]nformation\n");
    wlogprint("Or press any other key to continue\n");
    input = getch();

    if (!strncasecmp(&input, "a", 1))
    {
        input_pool(true);
        goto updated;
    }
    else if (!strncasecmp(&input, "r", 1))
    {
        if (total_pools <= 1)
        {
            wlogprint("Cannot remove last pool");
            goto retry;
        }
        selected = curses_int("Select pool number");
        if (selected < 0 || selected >= total_pools)
        {
            wlogprint("Invalid selection\n");
            goto retry;
        }
        pool = pools[selected];
        if (pool == current_pool())
            switch_pools(NULL);
        if (pool == current_pool())
        {
            wlogprint("Unable to remove pool due to activity\n");
            goto retry;
        }
        disable_pool(pool);
        remove_pool(pool);
        goto updated;
    }
    else if (!strncasecmp(&input, "s", 1))
    {
        selected = curses_int("Select pool number");
        if (selected < 0 || selected >= total_pools)
        {
            wlogprint("Invalid selection\n");
            goto retry;
        }
        pool = pools[selected];
        enable_pool(pool);
        switch_pools(pool);
        goto updated;
    }
    else if (!strncasecmp(&input, "d", 1))
    {
        if (enabled_pools <= 1)
        {
            wlogprint("Cannot disable last pool");
            goto retry;
        }
        selected = curses_int("Select pool number");
        if (selected < 0 || selected >= total_pools)
        {
            wlogprint("Invalid selection\n");
            goto retry;
        }
        pool = pools[selected];
        disable_pool(pool);
        if (pool == current_pool())
            switch_pools(NULL);
        goto updated;
    }
    else if (!strncasecmp(&input, "e", 1))
    {
        selected = curses_int("Select pool number");
        if (selected < 0 || selected >= total_pools)
        {
            wlogprint("Invalid selection\n");
            goto retry;
        }
        pool = pools[selected];
        enable_pool(pool);
        if (pool->prio < current_pool()->prio)
            switch_pools(pool);
        goto updated;
    }
    else if (!strncasecmp(&input, "c", 1))
    {
        for (i = 0; i <= TOP_STRATEGY; i++)
            wlogprint("%d: %s\n", i, strategies[i].s);
        selected = curses_int("Select strategy number type");
        if (selected < 0 || selected > TOP_STRATEGY)
        {
            wlogprint("Invalid selection\n");
            goto retry;
        }
        if (selected == POOL_ROTATE)
        {
            opt_rotate_period = curses_int("Select interval in minutes");

            if (opt_rotate_period < 0 || opt_rotate_period > 9999)
            {
                opt_rotate_period = 0;
                wlogprint("Invalid selection\n");
                goto retry;
            }
        }
        pool_strategy = selected;
        switch_pools(NULL);
        goto updated;
    }
    else if (!strncasecmp(&input, "i", 1))
    {
        selected = curses_int("Select pool number");
        if (selected < 0 || selected >= total_pools)
        {
            wlogprint("Invalid selection\n");
            goto retry;
        }
        pool = pools[selected];
        display_pool_summary(pool);
        goto retry;
    }
    else if (!strncasecmp(&input, "f", 1))
    {
        opt_fail_only ^= true;
        goto updated;
    }
    else
        clear_logwin();

    immedok(logwin, false);
    opt_loginput = false;
}

static void display_options(void)
{
    int selected;
    char input;

    opt_loginput = true;
    immedok(logwin, true);
    clear_logwin();
retry:
    wlogprint("[N]ormal [C]lear [S]ilent mode (disable all output)\n");
    wlogprint("[D]ebug:%s\n[P]er-device:%s\n[Q]uiet:%s\n[V]erbose:%s\n"
              "[R]PC debug:%s\n[W]orkTime details:%s\nco[M]pact: %s\n"
              "[L]og interval:%d\n[Z]ero statistics\n",
        opt_debug ? "on" : "off", want_per_device_stats ? "on" : "off", opt_quiet ? "on" : "off",
        opt_log_output ? "on" : "off", opt_protocol ? "on" : "off", opt_worktime ? "on" : "off",
        opt_compact ? "on" : "off", opt_log_interval);
    wlogprint("Select an option or any other key to return\n");
    input = getch();
    if (!strncasecmp(&input, "q", 1))
    {
        opt_quiet ^= true;
        wlogprint("Quiet mode %s\n", opt_quiet ? "enabled" : "disabled");
        goto retry;
    }
    else if (!strncasecmp(&input, "v", 1))
    {
        opt_log_output ^= true;
        if (opt_log_output)
            opt_quiet = false;
        wlogprint("Verbose mode %s\n", opt_log_output ? "enabled" : "disabled");
        goto retry;
    }
    else if (!strncasecmp(&input, "n", 1))
    {
        opt_log_output = false;
        opt_debug = false;
        opt_quiet = false;
        opt_protocol = false;
        opt_compact = false;
        want_per_device_stats = false;
        wlogprint("Output mode reset to normal\n");
        switch_compact();
        goto retry;
    }
    else if (!strncasecmp(&input, "d", 1))
    {
        opt_debug ^= true;
        opt_log_output = opt_debug;
        if (opt_debug)
            opt_quiet = false;
        wlogprint("Debug mode %s\n", opt_debug ? "enabled" : "disabled");
        goto retry;
    }
    else if (!strncasecmp(&input, "m", 1))
    {
        opt_compact ^= true;
        wlogprint("Compact mode %s\n", opt_compact ? "enabled" : "disabled");
        switch_compact();
        goto retry;
    }
    else if (!strncasecmp(&input, "p", 1))
    {
        want_per_device_stats ^= true;
        opt_log_output = want_per_device_stats;
        wlogprint("Per-device stats %s\n", want_per_device_stats ? "enabled" : "disabled");
        goto retry;
    }
    else if (!strncasecmp(&input, "r", 1))
    {
        opt_protocol ^= true;
        if (opt_protocol)
            opt_quiet = false;
        wlogprint("RPC protocol debugging %s\n", opt_protocol ? "enabled" : "disabled");
        goto retry;
    }
    else if (!strncasecmp(&input, "c", 1))
        clear_logwin();
    else if (!strncasecmp(&input, "l", 1))
    {
        selected = curses_int("Interval in seconds");
        if (selected < 0 || selected > 9999)
        {
            wlogprint("Invalid selection\n");
            goto retry;
        }
        opt_log_interval = selected;
        wlogprint("Log interval set to %d seconds\n", opt_log_interval);
        goto retry;
    }
    else if (!strncasecmp(&input, "s", 1))
    {
        opt_realquiet = true;
    }
    else if (!strncasecmp(&input, "w", 1))
    {
        opt_worktime ^= true;
        wlogprint("WorkTime details %s\n", opt_worktime ? "enabled" : "disabled");
        goto retry;
    }
    else if (!strncasecmp(&input, "z", 1))
    {
        zero_stats();
        goto retry;
    }
    else
        clear_logwin();

    immedok(logwin, false);
    opt_loginput = false;
}
#endif

void default_save_file(char* filename)
{
    if (default_config && *default_config)
    {
        strcpy(filename, default_config);
        return;
    }

#if defined(unix)
    if (getenv("HOME") && *getenv("HOME"))
    {
        strcpy(filename, getenv("HOME"));
        strcat(filename, "/");
    }
    else
        strcpy(filename, "");
    strcat(filename, ".cgminer/");
    mkdir(filename, 0777);
#else
    strcpy(filename, "");
#endif
    strcat(filename, def_conf);
}

#ifdef HAVE_CURSES
static void set_options(void)
{
    int selected;
    char input;

    opt_loginput = true;
    immedok(logwin, true);
    clear_logwin();
retry:
    wlogprint("[Q]ueue: %d\n[S]cantime: %d\n[E]xpiry: %d\n"
              "[W]rite config file\n[C]gminer restart\n",
        opt_queue, opt_scantime, opt_expiry);
    wlogprint("Select an option or any other key to return\n");
    input = getch();

    if (!strncasecmp(&input, "q", 1))
    {
        selected = curses_int("Extra work items to queue");
        if (selected < 0 || selected > 9999)
        {
            wlogprint("Invalid selection\n");
            goto retry;
        }
        opt_queue = selected;
        goto retry;
    }
    else if (!strncasecmp(&input, "s", 1))
    {
        selected = curses_int("Set scantime in seconds");
        if (selected < 0 || selected > 9999)
        {
            wlogprint("Invalid selection\n");
            goto retry;
        }
        opt_scantime = selected;
        goto retry;
    }
    else if (!strncasecmp(&input, "e", 1))
    {
        selected = curses_int("Set expiry time in seconds");
        if (selected < 0 || selected > 9999)
        {
            wlogprint("Invalid selection\n");
            goto retry;
        }
        opt_expiry = selected;
        goto retry;
    }
    else if (!strncasecmp(&input, "w", 1))
    {
        FILE* fcfg;
        char *str, filename[PATH_MAX], prompt[PATH_MAX + 50];

        default_save_file(filename);
        sprintf(prompt, "Config filename to write (Enter for default) [%s]", filename);
        str = curses_input(prompt);
        if (strcmp(str, "-1"))
        {
            struct stat statbuf;

            strcpy(filename, str);
            free(str);
            if (!stat(filename, &statbuf))
            {
                wlogprint("File exists, overwrite?\n");
                input = getch();
                if (strncasecmp(&input, "y", 1))
                    goto retry;
            }
        }
        else
            free(str);
        fcfg = fopen(filename, "w");
        if (!fcfg)
        {
            wlogprint("Cannot open or create file\n");
            goto retry;
        }
        write_config(fcfg);
        fclose(fcfg);
        goto retry;
    }
    else if (!strncasecmp(&input, "c", 1))
    {
        wlogprint("Are you sure?\n");
        input = getch();
        if (!strncasecmp(&input, "y", 1))
            app_restart();
        else
            clear_logwin();
    }
    else
        clear_logwin();

    immedok(logwin, false);
    opt_loginput = false;
}

static void* input_thread(void __maybe_unused* userdata)
{
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    RenameThread("input");

    if (!curses_active)
        return NULL;

    while (1)
    {
        char input;

        input = getch();
        if (!strncasecmp(&input, "q", 1))
        {
            kill_work();
            return NULL;
        }
        else if (!strncasecmp(&input, "d", 1))
        {
            display_options();
        }
        else if (!strncasecmp(&input, "p", 1))
        {
            display_pools();
        }
        else if (!strncasecmp(&input, "s", 1))
        {
            set_options();
        }
        else if (have_opencl && !strncasecmp(&input, "g", 1))
        {
#ifdef HAVE_OPENCL
            manage_gpu();
#endif
        }
        if (opt_realquiet)
        {
            disable_curses();
            break;
        }
    }

    return NULL;
}
#endif

static void* api_thread(void* userdata)
{
    struct thr_info* mythr = userdata;

    pthread_detach(pthread_self());
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    RenameThread("api");

    api(api_thr_id);

    PTH(mythr) = 0L;

    return NULL;
}

void thread_reportin(struct thr_info* thr)
{
    gettimeofday(&thr->last, NULL);
    thr->cgpu->status = LIFE_WELL;
    thr->getwork = false;
    thr->cgpu->device_last_well = time(NULL);
}

static inline void thread_reportout(struct thr_info* thr)
{
    thr->getwork = true;
}

static void hashmeter(int thr_id, struct timeval* diff, uint64_t hashes_done)
{
    struct timeval temp_tv_end, total_diff;
    double secs;
    double local_secs;
    double utility, efficiency = 0.0;
    static double local_mhashes_done = 0;
    static double rolling = 0;
    double local_mhashes;
    bool showlog = false;
    char displayed_hashes[16], displayed_rolling[16];
    uint64_t dh64, dr64;
    struct thr_info* thr;

    local_mhashes = (double)hashes_done / 1000000.0;
    /* Update the last time this thread reported in */
    if (thr_id >= 0)
    {
        thr = get_thread(thr_id);
        gettimeofday(&(thr->last), NULL);
        thr->cgpu->device_last_well = time(NULL);
    }

    secs = (double)diff->tv_sec + ((double)diff->tv_usec / 1000000.0);

    /* So we can call hashmeter from a non worker thread */
    if (thr_id >= 0)
    {
        struct cgpu_info* cgpu = thr->cgpu;
        double thread_rolling = 0.0;
        int i;

        applog(LOG_DEBUG, "[thread %d: %" PRIu64 " hashes, %.1f khash/sec]", thr_id, hashes_done,
            hashes_done / 1000 / secs);

        /* Rolling average for each thread and each device */
        decay_time(&thr->rolling, local_mhashes / secs);
        for (i = 0; i < cgpu->threads; i++)
            thread_rolling += cgpu->thr[i]->rolling;

        mutex_lock(&hash_lock);
        decay_time(&cgpu->rolling, thread_rolling);
        cgpu->total_mhashes += local_mhashes;
        mutex_unlock(&hash_lock);

        // If needed, output detailed, per-device stats
        if (want_per_device_stats)
        {
            struct timeval now;
            struct timeval elapsed;

            gettimeofday(&now, NULL);
            timersub(&now, &thr->cgpu->last_message_tv, &elapsed);
            if (opt_log_interval <= elapsed.tv_sec)
            {
                struct cgpu_info* cgpu = thr->cgpu;
                char logline[255];

                cgpu->last_message_tv = now;

                get_statline(logline, cgpu);
                if (!curses_active)
                {
                    printf("%s          \r", logline);
                    fflush(stdout);
                }
                else
                    applog(LOG_INFO, "%s", logline);
            }
        }
    }

    /* Totals are updated by all threads so can race without locking */
    mutex_lock(&hash_lock);
    gettimeofday(&temp_tv_end, NULL);
    timersub(&temp_tv_end, &total_tv_end, &total_diff);

    total_mhashes_done += local_mhashes;
    local_mhashes_done += local_mhashes;
    /* Only update the total every second */
    if (!total_diff.tv_sec)
        goto out_unlock;
    if (total_diff.tv_sec >= opt_log_interval)
        showlog = true;
    gettimeofday(&total_tv_end, NULL);

    local_secs = (double)total_diff.tv_sec + ((double)total_diff.tv_usec / 1000000.0);
    decay_time(&rolling, local_mhashes_done / local_secs);
    global_hashrate = roundl(rolling) * 1000000;

    timersub(&total_tv_end, &total_tv_start, &total_diff);
    total_secs = (double)total_diff.tv_sec + ((double)total_diff.tv_usec / 1000000.0);

    utility = total_accepted / total_secs * 60;
    efficiency = total_getworks ? total_accepted * 100.0 / total_getworks : 0.0;

    dh64 = (double)total_mhashes_done / total_secs * 1000000ull;
    dr64 = (double)rolling * 1000000ull;
    suffix_string(dh64, displayed_hashes, 4);
    suffix_string(dr64, displayed_rolling, 4);

    sprintf(statusline, "%s(%ds):%s (avg):%sh/s | Q:%d  A:%d  R:%d  HW:%d  E:%.0f%%  U:%.1f/m",
        want_per_device_stats ? "ALL " : "", opt_log_interval, displayed_rolling, displayed_hashes, total_getworks,
        total_accepted, total_rejected, hw_errors, efficiency, utility);


    local_mhashes_done = 0;
out_unlock:
    mutex_unlock(&hash_lock);
    if (showlog)
    {
        if (!curses_active)
        {
            printf("%s          \r", statusline);
            fflush(stdout);
        }
        else
            applog(LOG_INFO, "%s", statusline);
    }
}

static void stratum_share_result(json_t* val, json_t* res_val, json_t* err_val, struct stratum_share* sshare)
{
    struct work* work = sshare->work;
    char hashshow[65];
    uint32_t* hash32;
    hash32 = (uint32_t*)(work->nonce);
    sprintf(hashshow, "%08lx Diff %f%s", (unsigned long)(hash32), work->work_difficulty, work->block ? " BLOCK!" : "");
    share_result(val, res_val, err_val, work, hashshow, false, "");
}

/* Parses stratum json responses and tries to find the id that the request
 * matched to and treat it accordingly. */
static bool parse_stratum_response(struct pool* pool, char* s)
{
    json_t *val = NULL, *err_val, *res_val, *id_val;
    struct stratum_share* sshare;
    json_error_t err;
    bool ret = false;
    int id;

    val = JSON_LOADS(s, &err);
    if (!val)
    {
        applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
        goto out;
    }

    res_val = json_object_get(val, "result");
    err_val = json_object_get(val, "error");
    id_val = json_object_get(val, "id");

    if (json_is_null(id_val) || !id_val)
    {
        char* ss;

        if (err_val)
            ss = json_dumps(err_val, JSON_INDENT(3));
        else
            ss = strdup("(unknown reason)");

        applog(LOG_INFO, "JSON-RPC non method decode failed: %s", ss);

        free(ss);

        goto out;
    }

    id = json_integer_value(id_val);
    mutex_lock(&sshare_lock);
    HASH_FIND_INT(stratum_shares, &id, sshare);
    if (sshare)
    {
        HASH_DEL(stratum_shares, sshare);
        pool->sshares--;
    }
    mutex_unlock(&sshare_lock);
    if (!sshare)
    {
        if (json_is_true(res_val))
            applog(LOG_NOTICE, "Accepted untracked stratum share from pool %d", pool->pool_no);
        else
            applog(LOG_NOTICE, "Rejected untracked stratum share from pool %d", pool->pool_no);
        goto out;
    }
    stratum_share_result(val, res_val, err_val, sshare);
    free_work(sshare->work);
    free(sshare);

    ret = true;
out:
    if (val)
        json_decref(val);

    return ret;
}

void clear_stratum_shares(struct pool* pool)
{
    struct stratum_share *sshare, *tmpshare;
    double diff_cleared = 0;
    int cleared = 0;

    mutex_lock(&sshare_lock);
    HASH_ITER(hh, stratum_shares, sshare, tmpshare)
    {
        if (sshare->work->pool == pool)
        {
            HASH_DEL(stratum_shares, sshare);
            diff_cleared += sshare->work->work_difficulty;
            free_work(sshare->work);
            pool->sshares--;
            free(sshare);
            cleared++;
        }
    }
    mutex_unlock(&sshare_lock);

    if (cleared)
    {
        applog(LOG_WARNING, "Lost %d shares due to stratum disconnect on pool %d", cleared, pool->pool_no);
        pool->stale_shares += cleared;
        total_stale += cleared;
        pool->diff_stale += diff_cleared;
        total_diff_stale += diff_cleared;
    }
}

static void clear_pool_work(struct pool* pool)
{
    struct work *work, *tmp;
    int cleared = 0;

    mutex_lock(stgd_lock);
    HASH_ITER(hh, staged_work, work, tmp)
    {
        if (work->pool == pool)
        {
            HASH_DEL(staged_work, work);
            free_work(work);
            cleared++;
        }
    }
    mutex_unlock(stgd_lock);
}

static int cp_prio(void)
{
    int prio;

    cg_rlock(&control_lock);
    prio = currentpool->prio;
    cg_runlock(&control_lock);
    return prio;
}

/* We only need to maintain a secondary pool connection when we need the
 * capacity to get work from the backup pools while still on the primary */
static bool cnx_needed(struct pool* pool)
{
    struct pool* cp;

    /* Balance strategies need all pools online */
    if (pool_strategy == POOL_BALANCE)
        return true;
    if (pool_strategy == POOL_LOADBALANCE)
        return true;

    /* Idle stratum pool needs something to kick it alive again */
    if (pool->has_stratum && pool->idle)
        return true;

    /* Getwork pools without opt_fail_only need backup pools up to be able
     * to leak shares */
    cp = current_pool();
    if (cp == pool)
        return true;
    /* If we're waiting for a response from shares submitted, keep the
     * connection open. */
    if (pool->sshares)
        return true;
    /* If the pool has only just come to life and is higher priority than
     * the current pool keep the connection open so we can fail back to
     * it. */
    if (pool_strategy == POOL_FAILOVER && pool->prio < cp_prio())
        return true;
    if (pool_unworkable(cp))
        return true;
    return false;
}

static void wait_lpcurrent(struct pool* pool);
static void pool_resus(struct pool* pool);
static void gen_stratum_work(struct pool* pool, struct work* work);

static void stratum_resumed(struct pool* pool)
{
    if (!pool->stratum_notify)
        return;
    if (pool_tclear(pool, &pool->idle))
    {
        applog(LOG_INFO, "Stratum connection to pool %d resumed", pool->pool_no);
        pool_resus(pool);
    }
}

static bool supports_resume(struct pool* pool)
{
    bool ret;

    cg_rlock(&pool->data_lock);
    ret = (pool->sessionid != NULL);
    cg_runlock(&pool->data_lock);
    return ret;
}

/* One stratum thread per pool that has stratum waits on the socket checking
 * for new messages and for the integrity of the socket connection. We reset
 * the connection based on the integrity of the receive side only as the send
 * side will eventually expire data it fails to send. */
static void* stratum_thread(void* userdata)
{
    struct pool* pool = (struct pool*)userdata;
    char threadname[16];

    pthread_detach(pthread_self());

    snprintf(threadname, 16, "stratum/%d", pool->pool_no);
    RenameThread(threadname);

    while (42)
    {
        struct timeval timeout;
        int sel_ret;
        fd_set rd;
        char* s;

        if (unlikely(pool->removed))
            break;

        /* Check to see whether we need to maintain this connection
         * indefinitely or just bring it up when we switch to this
         * pool */
        if (!sock_full(pool) && !cnx_needed(pool))
        {
            suspend_stratum(pool);
            clear_stratum_shares(pool);
            clear_pool_work(pool);

            wait_lpcurrent(pool);
            if (!restart_stratum(pool))
            {
                pool_died(pool);
                while (!restart_stratum(pool))
                {
                    if (pool->removed)
                        goto out;
                    nmsleep(30000);
                }
            }
        }

        FD_ZERO(&rd);
        FD_SET(pool->sock, &rd);
        timeout.tv_sec = 90;
        timeout.tv_usec = 0;

        /* The protocol specifies that notify messages should be sent
         * every minute so if we fail to receive any for 90 seconds we
         * assume the connection has been dropped and treat this pool
         * as dead */
        if (!sock_full(pool) && (sel_ret = select(pool->sock + 1, &rd, NULL, NULL, &timeout)) < 1)
        {
            applog(LOG_DEBUG, "Stratum select failed on pool %d with value %d", pool->pool_no, sel_ret);
            s = NULL;
        }
        else
            s = recv_line(pool);
        if (!s)
        {
            applog(LOG_NOTICE, "Stratum connection to pool %d interrupted", pool->pool_no);
            pool->getfail_occasions++;
            total_go++;

            /* If the socket to our stratum pool disconnects, all
             * tracked submitted shares are lost and we will leak
             * the memory if we don't discard their records. */
            if (!supports_resume(pool))
                clear_stratum_shares(pool);
            clear_pool_work(pool);
            if (pool == current_pool())
                restart_threads();

            if (restart_stratum(pool))
                continue;

            pool_died(pool);
            while (!restart_stratum(pool))
            {
                if (pool->removed)
                    goto out;
                nmsleep(30000);
            }
            stratum_resumed(pool);
            continue;
        }

        /* Check this pool hasn't died while being a backup pool and
         * has not had its idle flag cleared */
        stratum_resumed(pool);

        if (!parse_method(pool, s) && !parse_stratum_response(pool, s))
            applog(LOG_INFO, "Unknown stratum msg: %s", s);
        free(s);
        if (pool->swork.clean)
        {
            struct work* work = make_work();

            /* Generate a single work item to update the current
             * block database */
            pool->swork.clean = false;
            gen_stratum_work(pool, work);
            if (test_work_current(work))
            {
                /* Only accept a work restart if this stratum
                 * connection is from the current pool */
                if (pool == current_pool())
                {
                    restart_threads();
                    applog(LOG_NOTICE, "Stratum from pool %d requested work restart", pool->pool_no);
                }
            }
            else
                applog(LOG_NOTICE, "Stratum from pool %d detected new block", pool->pool_no);
            free_work(work);
        }
    }

out:
    return NULL;
}

static void init_stratum_thread(struct pool* pool)
{
    if (unlikely(pthread_create(&pool->stratum_thread, NULL, stratum_thread, (void*)pool)))
        nxquit(1, "Failed to create stratum thread");
}

static bool stratum_works(struct pool* pool)
{
    applog(LOG_INFO, "Testing pool %d stratum %s", pool->pool_no, pool->stratum_url);
    if (!extract_sockaddr(pool, pool->stratum_url))
        return false;

    if (!initiate_stratum(pool))
        return false;

    return true;
}

static bool pool_active(struct pool* pool, bool pinging)
{
    struct timeval tv_getwork;
    struct timeval tv_getwork_reply;
    bool ret = false;

    applog(LOG_INFO, "Testing pool %s", pool->rpc_url);

    /* This is the central point we activate stratum when we can */
retry_stratum:
    if (pool->has_stratum)
    {
        /* We create the stratum thread for each pool just after
         * successful authorisation. Once the init flag has been set
         * we never unset it and the stratum thread is responsible for
         * setting/unsetting the active flag */
        bool init = pool_tset(pool, &pool->stratum_init);

        if (!init)
        {
            bool ret = initiate_stratum(pool) && auth_stratum(pool);

            if (ret)
                init_stratum_thread(pool);
            else
                pool_tclear(pool, &pool->stratum_init);
            return ret;
        }
        return pool->stratum_active;
    }
    return ret;
}

static void pool_resus(struct pool* pool)
{
    if (pool_strategy == POOL_FAILOVER && pool->prio < cp_prio())
    {
        applog(LOG_WARNING, "Pool %d %s alive", pool->pool_no, pool->rpc_url);
        switch_pools(NULL);
    }
    else
        applog(LOG_INFO, "Pool %d %s alive", pool->pool_no, pool->rpc_url);
}

static struct work* hash_pop(void)
{
    struct work *work = NULL, *tmp;
    int hc;

    mutex_lock(stgd_lock);
    while (!getq->frozen && !HASH_COUNT(staged_work))
        pthread_cond_wait(&getq->cond, stgd_lock);

    hc = HASH_COUNT(staged_work);
    /* Find clone work if possible, to allow masters to be reused */
    if (hc > staged_rollable)
    {
        HASH_ITER(hh, staged_work, work, tmp)
        {
            if (!work_rollable(work))
                break;
        }
    }
    else
        work = staged_work;
    HASH_DEL(staged_work, work);
    if (work_rollable(work))
        staged_rollable--;

    /* Signal the getwork scheduler to look for more work */
    pthread_cond_signal(&gws_cond);

    /* Signal hash_pop again in case there are mutliple hash_pop waiters */
    pthread_cond_signal(&getq->cond);
    mutex_unlock(stgd_lock);

    return work;
}

/* Diff 1 is a 256 bit unsigned integer of
 * 0x00000000ffff0000000000000000000000000000000000000000000000000000
 * so we use a big endian 64 bit unsigned integer centred on the 5th byte to
 * cover a huge range of difficulty targets, though not all 256 bits' worth */
static void set_work_target(struct work *work, double diff)
{
	uint8_t target[32];
    memset(target, 0, 32);
    bool pfNegative;
    bool pfOverflow;
    difficulty_to_target(diff, target);

	if (opt_debug)
    {
		char *htarget = bin2hex(target, 32);

		applog(LOG_DEBUG, "Generated target %s", htarget);
		free(htarget);
	}
	memcpy(work->target, target, 32);
}

/* Generates stratum based work based on the most recent notify information
 * from the pool. This will keep generating work while a pool is down so we use
 * other means to detect when the pool has died in stratum_thread */
static void gen_stratum_work(struct pool* pool, struct work* work)
{
    uint32_t* data32;
    uint32_t* swap32;
    size_t alloc_len;
    int i;

    /* Use intermediate lock to update the one pool variable */
    cg_ilock(&pool->data_lock);

    /* Downgrade to a read lock to read off the pool variables */
    cg_dlock(&pool->data_lock);
    align_len(&alloc_len);

    /* Store the stratum work diff to check it still matches the pool's
     * stratum diff when submitting shares */
    work->sdiff = pool->swork.diff;

    /* Copy parameters required for share submission */
    work->job_id = strdup(pool->swork.job_id);
    work->ntime = strdup(pool->swork.ntime);
    cg_runlock(&pool->data_lock);

    applog(LOG_DEBUG, "Work job_id %s ntime %s", work->job_id, work->ntime);

    local_work++;
    work->pool = pool;
    work->stratum = true;
    memcpy(work->start_nonce, pool->swork.start_nonce, 16);
    work->id = total_work++;
    work->nBits = pool->swork.nBits;
    work->candidateId = pool->swork.candidateId;
    memcpy(work->headerCommitment, pool->swork.headerCommitment, 32);
    work->getwork_mode = GETWORK_MODE_STRATUM;
    work->work_block = work_block;
    calc_diff(work, work->sdiff);
    set_work_target(work, work->work_difficulty);

    gettimeofday(&work->tv_staged, NULL);
}

static struct work* get_work(struct thr_info* thr, const int thr_id)
{
    struct work* work = NULL;

    /* Tell the watchdog thread this thread is waiting on getwork and
     * should not be restarted */
    thread_reportout(thr);

    applog(LOG_DEBUG, "Popping work from get queue to get work");
    while (!work)
    {
        work = hash_pop();
        if (stale_work(work, false))
        {
            discard_work(work);
            work = NULL;
            wake_gws();
        }
    }
    applog(LOG_DEBUG, "Got work from get queue to get work for thread %d", thr_id);

    work->thr_id = thr_id;
    thread_reportin(thr);
    work->mined = true;
    return work;
}

void submit_work_async(struct work* work_in, struct timeval* tv_work_found)
{
    struct work* work = copy_work(work_in);
    pthread_t submit_thread;

    if (tv_work_found)
    {
        memcpy(&(work->tv_work_found), tv_work_found, sizeof(struct timeval));
    }
    applog(LOG_DEBUG, "Pushing submit work to work thread");
    if (unlikely(pthread_create(&submit_thread, NULL, submit_work_thread, (void*)work)))
    {
        nxquit(1, "Failed to create submit_work_thread");
    }
}

void submit_nonce(struct thr_info* thr, struct work* work, uint32_t nonce)
{
    struct timeval tv_work_found;
    gettimeofday(&tv_work_found, NULL);
    mutex_lock(&stats_lock);
    total_diff1 += work->device_diff;
    thr->cgpu->diff1 += work->device_diff;
    work->pool->diff1 += work->device_diff;
    mutex_unlock(&stats_lock);

    submit_work_async(work, &tv_work_found);
}

static inline bool abandon_work(struct work* work, struct timeval* wdiff, uint64_t hashes)
{
    if (wdiff->tv_sec > opt_scantime || hashes >= 0xfffffffe || stale_work(work, false))
    {
        return true;
    }
    return false;
}

static void mt_disable(struct thr_info* mythr, const int thr_id, struct device_drv* drv)
{
    applog(LOG_WARNING, "Thread %d being disabled", thr_id);
    mythr->rolling = mythr->cgpu->rolling = 0;
    applog(LOG_DEBUG, "Popping wakeup ping in miner thread");
    thread_reportout(mythr);
    do
    {
        tq_pop(mythr->q, NULL); /* Ignore ping that's popped */
    } while (mythr->pause);
    thread_reportin(mythr);
    applog(LOG_WARNING, "Thread %d being re-enabled", thr_id);
    drv->thread_enable(mythr);
}

/* The main hashing loop for devices that are slow enough to work on one work
 * item at a time, without a queue, aborting work before the entire nonce
 * range has been hashed if needed. */
static void hash_sole_work(struct thr_info* mythr)
{
    const int thr_id = mythr->id;
    struct cgpu_info* cgpu = mythr->cgpu;
    struct device_drv* drv = cgpu->drv;
    struct timeval getwork_start, tv_start, tv_end, tv_workstart, tv_lastupdate;
    struct cgminer_stats* dev_stats = &(cgpu->cgminer_stats);
    struct cgminer_stats* pool_stats;
    /* Try to cycle approximately 5 times before each log update */
    const long cycle = opt_log_interval / 5 ?: 1;
    const bool primary = (!mythr->device_thread) || mythr->primary_thread;
    struct timeval diff, sdiff, wdiff = {0, 0};
    uint8_t max_nonce[16];
    drv->can_limit_work(mythr, max_nonce);
    int64_t hashes_done = 0;

    gettimeofday(&getwork_start, NULL);
    sdiff.tv_sec = sdiff.tv_usec = 0;
    gettimeofday(&tv_lastupdate, NULL);

    while (42)
    {
        struct work* work = get_work(mythr, thr_id);
        int64_t hashes;

        mythr->work_restart = false;
        cgpu->new_work = true;

        gettimeofday(&tv_workstart, NULL);
        if (memcmp(mythr->lastCommitment, work->headerCommitment, 32) != 0 || memcmp(mythr->lastCommitment, UINT256_ZERO, 32) == 0)
        {
            // we have not started mining on the device nonce range, pull nonce from work start nonce
            memcpy(work->nonce, work->start_nonce, 16);
            /*
            printf("pool provided start nonce: ");
            uint128_print_string(work->nonce);
            printf("\n");
            */
            // work nonce is little endian
            const uint64_t THREAD_NONCE_RANGE_SIZE = POOL137_NONCE_RANGE / total_devices;
            uint64_t nonce_start_offset = cgpu->device_id * THREAD_NONCE_RANGE_SIZE;
            // add the start offset for this thread to the work nonce
            nonce_assign_addition(work->nonce, nonce_start_offset);
            /*
            printf("start nonce for thread post assign addition: ");
            uint128_print_string(work->nonce);
            printf("\n");
            */
            memcpy(mythr->thread_nonce, work->nonce, 16);
            memcpy(mythr->lastCommitment, work->headerCommitment, 32);
        }
        else
        {
            // we have already started mining on the device nonce range
            memcpy(work->nonce, mythr->thread_nonce, 16);
        }
        cgpu->max_hashes = 0;
        if (!drv->prepare_work(mythr, work))
        {
            applog(LOG_ERR,
                "work prepare failed, exiting "
                "mining thread %d",
                thr_id);
            break;
        }
        work->device_diff = MIN(drv->max_diff, work->work_difficulty);

        do
        {
            gettimeofday(&tv_start, NULL);

            timersub(&tv_start, &getwork_start, &getwork_start);

            timeradd(&getwork_start, &(dev_stats->getwork_wait), &(dev_stats->getwork_wait));
            if (timercmp(&getwork_start, &(dev_stats->getwork_wait_max), >))
            {
                dev_stats->getwork_wait_max.tv_sec = getwork_start.tv_sec;
                dev_stats->getwork_wait_max.tv_usec = getwork_start.tv_usec;
            }
            if (timercmp(&getwork_start, &(dev_stats->getwork_wait_min), <))
            {
                dev_stats->getwork_wait_min.tv_sec = getwork_start.tv_sec;
                dev_stats->getwork_wait_min.tv_usec = getwork_start.tv_usec;
            }
            dev_stats->getwork_calls++;

            pool_stats = &(work->pool->cgminer_stats);

            timeradd(&getwork_start, &(pool_stats->getwork_wait), &(pool_stats->getwork_wait));
            if (timercmp(&getwork_start, &(pool_stats->getwork_wait_max), >))
            {
                pool_stats->getwork_wait_max.tv_sec = getwork_start.tv_sec;
                pool_stats->getwork_wait_max.tv_usec = getwork_start.tv_usec;
            }
            if (timercmp(&getwork_start, &(pool_stats->getwork_wait_min), <))
            {
                pool_stats->getwork_wait_min.tv_sec = getwork_start.tv_sec;
                pool_stats->getwork_wait_min.tv_usec = getwork_start.tv_usec;
            }
            pool_stats->getwork_calls++;

            gettimeofday(&(work->tv_work_start), NULL);

            thread_reportin(mythr);
            hashes = drv->scanhash(mythr, work, max_nonce);
            thread_reportin(mythr);

            gettimeofday(&getwork_start, NULL);

            if (unlikely(hashes == -1))
            {
                applog(LOG_ERR, "%s %d failure, disabling!", drv->name, cgpu->device_id);
                cgpu->deven = DEV_DISABLED;
                dev_error(cgpu, REASON_THREAD_ZERO_HASH);
                mt_disable(mythr, thr_id, drv);
            }
            hashes_done += hashes;
            if (hashes > cgpu->max_hashes)
            {
                cgpu->max_hashes = hashes;
            }
            gettimeofday(&tv_end, NULL);
            timersub(&tv_end, &tv_start, &diff);
            sdiff.tv_sec += diff.tv_sec;
            sdiff.tv_usec += diff.tv_usec;
            if (sdiff.tv_usec > 1000000)
            {
                ++sdiff.tv_sec;
                sdiff.tv_usec -= 1000000;
            }
            timersub(&tv_end, &tv_workstart, &wdiff);
            timersub(&tv_end, &tv_lastupdate, &diff);
            /* Update the hashmeter at most 5 times per second */
            if (diff.tv_sec > 0 || diff.tv_usec > 200)
            {
                hashmeter(thr_id, &diff, hashes_done);
                hashes_done = 0;
                memcpy(&tv_lastupdate, &tv_end, sizeof(struct timeval));
            }
            if (unlikely(mythr->work_restart))
            {
                /* Apart from device_thread 0, we stagger the
                 * starting of every next thread to try and get
                 * all devices busy before worrying about
                 * getting work for their extra threads */
                if (!primary)
                {
                    struct timespec rgtp;

                    rgtp.tv_sec = 0;
                    rgtp.tv_nsec = 250 * mythr->device_thread * 1000000;
                    nanosleep(&rgtp, NULL);
                }
                break;
            }
            if (unlikely(mythr->pause || cgpu->deven != DEV_ENABLED))
            {
                mt_disable(mythr, thr_id, drv);
            }
            sdiff.tv_sec = sdiff.tv_usec = 0;
        } while (!abandon_work(work, &wdiff, cgpu->max_hashes));
        free_work(work);
    }
}

void* miner_thread(void* userdata)
{
    struct thr_info* mythr = userdata;
    const int thr_id = mythr->id;
    struct cgpu_info* cgpu = mythr->cgpu;
    struct device_drv* drv = cgpu->drv;
    char threadname[24];

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    snprintf(threadname, 24, "miner/%d", thr_id);
    RenameThread(threadname);

    if (!drv->thread_init(mythr))
    {
        dev_error(cgpu, REASON_THREAD_FAIL_INIT);
        goto out;
    }

    thread_reportout(mythr);
    applog(LOG_DEBUG, "Popping ping in miner thread");
    tq_pop(mythr->q, NULL); /* Wait for a ping to start */

    drv->hash_work(mythr);
out:
    drv->thread_shutdown(mythr);

    thread_reportin(mythr);
    applog(LOG_ERR, "Thread %d failure, exiting", thr_id);
    tq_freeze(mythr->q);

    return NULL;
}

enum
{
    STAT_SLEEP_INTERVAL = 1,
    STAT_CTR_INTERVAL = 10000000,
    FAILURE_INTERVAL = 30,
};

/* This will make the longpoll thread wait till it's the current pool, or it
 * has been flagged as rejecting, before attempting to open any connections.
 */
static void wait_lpcurrent(struct pool* pool)
{
    if (cnx_needed(pool))
        return;

    while (pool != current_pool() && pool_strategy != POOL_LOADBALANCE && pool_strategy != POOL_BALANCE)
    {
        mutex_lock(&lp_lock);
        pthread_cond_wait(&lp_cond, &lp_lock);
        mutex_unlock(&lp_lock);
    }
}

void reinit_device(struct cgpu_info* cgpu)
{
    cgpu->drv->reinit_device(cgpu);
}

static struct timeval rotate_tv;

/* We reap curls if they are unused for over a minute */
static void reap_curl(struct pool* pool)
{
    struct curl_ent *ent, *iter;
    struct timeval now;
    int reaped = 0;

    gettimeofday(&now, NULL);
    mutex_lock(&pool->pool_lock);
    list_for_each_entry_safe(ent, iter, &pool->curlring, node)
    {
        if (pool->curls < 2)
            break;
        if (now.tv_sec - ent->tv.tv_sec > 300)
        {
            reaped++;
            pool->curls--;
            list_del(&ent->node);
            curl_easy_cleanup(ent->curl);
            free(ent);
        }
    }
    mutex_unlock(&pool->pool_lock);
    if (reaped)
        applog(LOG_DEBUG, "Reaped %d curl%s from pool %d", reaped, reaped > 1 ? "s" : "", pool->pool_no);
}

static void* watchpool_thread(void __maybe_unused* userdata)
{
    int intervals = 0;

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    RenameThread("watchpool");

    while (42)
    {
        struct timeval now;
        int i;

        if (++intervals > 20)
            intervals = 0;
        gettimeofday(&now, NULL);

        for (i = 0; i < total_pools; i++)
        {
            struct pool* pool = pools[i];

            if (!opt_benchmark)
                reap_curl(pool);

            /* Get a rolling utility per pool over 10 mins */
            if (intervals > 19)
            {
                int shares = pool->diff1 - pool->last_shares;

                pool->last_shares = pool->diff1;
                pool->utility = (pool->utility + (double)shares * 0.63) / 1.63;
                pool->shares = pool->utility;
            }

            if (pool->enabled == POOL_DISABLED)
                continue;

            /* Don't start testing any pools if the test threads
             * from startup are still doing their first attempt. */
            if (unlikely(pool->testing))
            {
                pthread_join(pool->test_thread, NULL);
                pool->testing = false;
            }

            /* Test pool is idle once every minute */
            if (pool->idle && now.tv_sec - pool->tv_idle.tv_sec > 30)
            {
                gettimeofday(&pool->tv_idle, NULL);
                if (pool_active(pool, true) && pool_tclear(pool, &pool->idle))
                    pool_resus(pool);
            }
        }

        if (pool_strategy == POOL_ROTATE && now.tv_sec - rotate_tv.tv_sec > 60 * opt_rotate_period)
        {
            gettimeofday(&rotate_tv, NULL);
            switch_pools(NULL);
        }

        nmsleep(30000);
    }
    return NULL;
}

/* Makes sure the hashmeter keeps going even if mining threads stall, updates
 * the screen at regular intervals, and restarts threads if they appear to have
 * died. */
#define WATCHDOG_INTERVAL   2
#define WATCHDOG_SICK_TIME  60
#define WATCHDOG_DEAD_TIME  600
#define WATCHDOG_SICK_COUNT (WATCHDOG_SICK_TIME / WATCHDOG_INTERVAL)
#define WATCHDOG_DEAD_COUNT (WATCHDOG_DEAD_TIME / WATCHDOG_INTERVAL)

static void* watchdog_thread(void __maybe_unused* userdata)
{
    const unsigned int interval = WATCHDOG_INTERVAL;
    struct timeval zero_tv;

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    RenameThread("watchdog");

    memset(&zero_tv, 0, sizeof(struct timeval));
    gettimeofday(&rotate_tv, NULL);

    while (1)
    {
        int i;
        struct timeval now;

        sleep(interval);

        discard_stale();

        hashmeter(-1, &zero_tv, 0);

#ifdef HAVE_CURSES
        if (curses_active_locked())
        {
            change_logwinsize();
            curses_print_status();
            for (i = 0; i < mining_threads; i++)
                curses_print_devstatus(i);
            touchwin(statuswin);
            wrefresh(statuswin);
            touchwin(logwin);
            wrefresh(logwin);
            unlock_curses();
        }
#endif

        gettimeofday(&now, NULL);

        if (!sched_paused && !should_run())
        {
            applog(LOG_WARNING, "Pausing execution as per stop time %02d:%02d scheduled", schedstop.tm.tm_hour,
                schedstop.tm.tm_min);
            if (!schedstart.enable)
            {
                nxquit(0, "Terminating execution as planned");
                break;
            }

            applog(LOG_WARNING, "Will restart execution as scheduled at %02d:%02d", schedstart.tm.tm_hour,
                schedstart.tm.tm_min);
            sched_paused = true;
            rd_lock(&mining_thr_lock);
            for (i = 0; i < mining_threads; i++)
                mining_thr[i]->pause = true;
            rd_unlock(&mining_thr_lock);
        }
        else if (sched_paused && should_run())
        {
            applog(LOG_WARNING, "Restarting execution as per start time %02d:%02d scheduled", schedstart.tm.tm_hour,
                schedstart.tm.tm_min);
            if (schedstop.enable)
                applog(LOG_WARNING, "Will pause execution as scheduled at %02d:%02d", schedstop.tm.tm_hour,
                    schedstop.tm.tm_min);
            sched_paused = false;

            for (i = 0; i < mining_threads; i++)
            {
                struct thr_info* thr;

                thr = get_thread(i);

                /* Don't touch disabled devices */
                if (thr->cgpu->deven == DEV_DISABLED)
                    continue;
                thr->pause = false;
                tq_push(thr->q, &ping);
            }
        }

        for (i = 0; i < total_devices; ++i)
        {
            struct cgpu_info* cgpu = get_devices(i);
            struct thr_info* thr = cgpu->thr[0];
            enum dev_enable* denable;
            char dev_str[8];
            int gpu;

            cgpu->drv->get_stats(cgpu);

            gpu = cgpu->device_id;
            denable = &cgpu->deven;
            sprintf(dev_str, "%s%d", cgpu->drv->name, gpu);

#ifdef HAVE_ADL
            if (adl_active && cgpu->has_adl)
                gpu_autotune(gpu, denable);
            if (opt_debug && cgpu->has_adl)
            {
                int engineclock = 0, memclock = 0, activity = 0, fanspeed = 0, fanpercent = 0, powertune = 0;
                float temp = 0, vddc = 0;

                if (gpu_stats(
                        gpu, &temp, &engineclock, &memclock, &vddc, &activity, &fanspeed, &fanpercent, &powertune))
                    applog(LOG_DEBUG, "%.1f C  F: %d%%(%dRPM)  E: %dMHz  M: %dMhz  V: %.3fV  A: %d%%  P: %d%%", temp,
                        fanpercent, fanspeed, engineclock, memclock, vddc, activity, powertune);
            }
#endif

            /* Thread is waiting on getwork or disabled */
            if (thr->getwork || *denable == DEV_DISABLED)
                continue;

#ifdef WANT_CPUMINE
            if (cgpu->drv->drv_id == DRIVER_CPU)
                continue;
#endif
            if (cgpu->status != LIFE_WELL && (now.tv_sec - thr->last.tv_sec < WATCHDOG_SICK_TIME))
            {
                if (cgpu->status != LIFE_INIT)
                    applog(LOG_ERR, "%s: Recovered, declaring WELL!", dev_str);
                cgpu->status = LIFE_WELL;
                cgpu->device_last_well = time(NULL);
            }
            else if (cgpu->status == LIFE_WELL && (now.tv_sec - thr->last.tv_sec > WATCHDOG_SICK_TIME))
            {
                thr->rolling = cgpu->rolling = 0;
                cgpu->status = LIFE_SICK;
                applog(LOG_ERR, "%s: Idle for more than 60 seconds, declaring SICK!", dev_str);
                gettimeofday(&thr->sick, NULL);

                dev_error(cgpu, REASON_DEV_SICK_IDLE_60);
#ifdef HAVE_ADL
                if (adl_active && cgpu->has_adl && gpu_activity(gpu) > 50)
                {
                    applog(LOG_ERR, "GPU still showing activity suggesting a hard hang.");
                    applog(LOG_ERR, "Will not attempt to auto-restart it.");
                }
                else
#endif
                    if (opt_restart)
                {
                    applog(LOG_ERR, "%s: Attempting to restart", dev_str);
                    reinit_device(cgpu);
                }
            }
            else if (cgpu->status == LIFE_SICK && (now.tv_sec - thr->last.tv_sec > WATCHDOG_DEAD_TIME))
            {
                cgpu->status = LIFE_DEAD;
                applog(LOG_ERR, "%s: Not responded for more than 10 minutes, declaring DEAD!", dev_str);
                gettimeofday(&thr->sick, NULL);

                dev_error(cgpu, REASON_DEV_DEAD_IDLE_600);
            }
            else if (now.tv_sec - thr->sick.tv_sec > 60 && (cgpu->status == LIFE_SICK || cgpu->status == LIFE_DEAD))
            {
                /* Attempt to restart a GPU that's sick or dead once every minute */
                gettimeofday(&thr->sick, NULL);
#ifdef HAVE_ADL
                if (adl_active && cgpu->has_adl && gpu_activity(gpu) > 50)
                {
                    /* Again do not attempt to restart a device that may have hard hung */
                }
                else
#endif
                    if (opt_restart)
                    reinit_device(cgpu);
            }
        }
    }

    return NULL;
}

static void log_print_status(struct cgpu_info* cgpu)
{
    char logline[255];

    get_statline(logline, cgpu);
    applog(LOG_WARNING, "%s", logline);
}

void print_summary(void)
{
    struct timeval diff;
    int hours, mins, secs, i;
    double utility, efficiency = 0.0, displayed_hashes, work_util;
    bool mhash_base = true;

    timersub(&total_tv_end, &total_tv_start, &diff);
    hours = diff.tv_sec / 3600;
    mins = (diff.tv_sec % 3600) / 60;
    secs = diff.tv_sec % 60;

    utility = total_accepted / total_secs * 60;
    efficiency = total_getworks ? total_accepted * 100.0 / total_getworks : 0.0;
    work_util = total_diff1 / total_secs * 60;

    applog(LOG_WARNING, "\nSummary of runtime statistics:\n");
    applog(LOG_WARNING, "Started at %s", datestamp);
    if (total_pools == 1)
        applog(LOG_WARNING, "Pool: %s", pools[0]->rpc_url);
#ifdef WANT_CPUMINE
    if (opt_n_threads)
        applog(LOG_WARNING, "CPU hasher algorithm used: %s", algo_names[opt_algo]);
#endif
    applog(LOG_WARNING, "Runtime: %d hrs : %d mins : %d secs", hours, mins, secs);
    displayed_hashes = total_mhashes_done / total_secs;
    if (displayed_hashes < 1)
    {
        displayed_hashes *= 1000;
        mhash_base = false;
    }

    applog(LOG_WARNING, "Average hashrate: %.1f %shash/s", displayed_hashes, mhash_base ? "Mega" : "Kilo");
    applog(LOG_WARNING, "Solved blocks: %d", found_blocks);
    applog(LOG_WARNING, "Best share difficulty: %s", best_share);
    applog(LOG_WARNING, "Queued work requests: %d", total_getworks);
    applog(LOG_WARNING, "Share submissions: %d", total_accepted + total_rejected);
    applog(LOG_WARNING, "Accepted shares: %d", total_accepted);
    applog(LOG_WARNING, "Rejected shares: %d", total_rejected);
    applog(LOG_WARNING, "Accepted difficulty shares: %1.f", total_diff_accepted);
    applog(LOG_WARNING, "Rejected difficulty shares: %1.f", total_diff_rejected);
    if (total_accepted || total_rejected)
        applog(LOG_WARNING, "Reject ratio: %.1f%%",
            (double)(total_rejected * 100) / (double)(total_accepted + total_rejected));
    applog(LOG_WARNING, "Hardware errors: %d", hw_errors);
    applog(LOG_WARNING, "Efficiency (accepted / queued): %.0f%%", efficiency);
    applog(LOG_WARNING, "Utility (accepted shares / min): %.2f/min", utility);
    applog(LOG_WARNING, "Work Utility (diff1 shares solved / min): %.2f/min\n", work_util);

    applog(LOG_WARNING, "Discarded work due to new blocks: %d", total_discarded);
    applog(LOG_WARNING, "Stale submissions discarded due to new blocks: %d", total_stale);
    applog(LOG_WARNING, "Unable to get work from server occasions: %d", total_go);
    applog(LOG_WARNING, "Work items generated locally: %d", local_work);
    applog(LOG_WARNING, "Submitting work remotely delay occasions: %d", total_ro);
    applog(LOG_WARNING, "New blocks detected on network: %d\n", new_blocks);

    if (total_pools > 1)
    {
        for (i = 0; i < total_pools; i++)
        {
            struct pool* pool = pools[i];

            applog(LOG_WARNING, "Pool: %s", pool->rpc_url);
            if (pool->solved)
                applog(LOG_WARNING, "SOLVED %d BLOCK%s!", pool->solved, pool->solved > 1 ? "S" : "");
            applog(LOG_WARNING, " Queued work requests: %d", pool->getwork_requested);
            applog(LOG_WARNING, " Share submissions: %d", pool->accepted + pool->rejected);
            applog(LOG_WARNING, " Accepted shares: %d", pool->accepted);
            applog(LOG_WARNING, " Rejected shares: %d", pool->rejected);
            applog(LOG_WARNING, " Accepted difficulty shares: %1.f", pool->diff_accepted);
            applog(LOG_WARNING, " Rejected difficulty shares: %1.f", pool->diff_rejected);
            if (pool->accepted || pool->rejected)
                applog(LOG_WARNING, " Reject ratio: %.1f%%",
                    (double)(pool->rejected * 100) / (double)(pool->accepted + pool->rejected));
            efficiency = pool->getwork_requested ? pool->accepted * 100.0 / pool->getwork_requested : 0.0;
            applog(LOG_WARNING, " Efficiency (accepted / queued): %.0f%%", efficiency);

            applog(LOG_WARNING, " Discarded work due to new blocks: %d", pool->discarded_work);
            applog(LOG_WARNING, " Stale submissions discarded due to new blocks: %d", pool->stale_shares);
            applog(LOG_WARNING, " Unable to get work from server occasions: %d", pool->getfail_occasions);
            applog(LOG_WARNING, " Submitting work remotely delay occasions: %d\n", pool->remotefail_occasions);
        }
    }

    applog(LOG_WARNING, "Summary of per device statistics:\n");
    for (i = 0; i < total_devices; ++i)
    {
        struct cgpu_info* cgpu = get_devices(i);

        log_print_status(cgpu);
    }

    if (opt_shares)
        applog(LOG_WARNING, "Mined %d accepted shares of %d requested\n", total_accepted, opt_shares);
    fflush(stdout);
    fflush(stderr);
    if (opt_shares > total_accepted)
        applog(LOG_WARNING, "WARNING - Mined only %d shares of %d requested.", total_accepted, opt_shares);
}

static void ECC_Stop()
{
    secp256k1_context* ctx = secp256k1_context_sign;
    secp256k1_context_sign = NULL;

    if (ctx)
    {
        secp256k1_context_destroy(ctx);
    }
}

static void clean_up(void)
{
#ifdef HAVE_OPENCL
    clear_adl(nDevs);
#endif

    gettimeofday(&total_tv_end, NULL);
#ifdef HAVE_CURSES
    disable_curses();
#endif
    if (!opt_realquiet && successful_connect)
        print_summary();

    if (opt_n_threads)
        free(cpus);

    curl_global_cleanup();
    ECC_Stop();
}

void nxquit(int status, const char* format, ...)
{
    va_list ap;

    clean_up();

    if (format)
    {
        va_start(ap, format);
        vfprintf(stderr, format, ap);
        va_end(ap);
    }
    fprintf(stderr, "\n");
    fflush(stderr);

#if defined(unix)
    if (forkpid > 0)
    {
        kill(forkpid, SIGTERM);
        forkpid = 0;
    }
#endif

    exit(status);
}

#ifdef HAVE_CURSES
char* curses_input(const char* query)
{
    char* input;

    echo();
    input = malloc(255);
    if (!input)
        nxquit(1, "Failed to malloc input");
    leaveok(logwin, false);
    wlogprint("%s:\n", query);
    wgetnstr(logwin, input, 255);
    if (!strlen(input))
        strcpy(input, "-1");
    leaveok(logwin, true);
    noecho();
    return input;
}
#endif

static bool pools_active = false;

static void* test_pool_thread(void* arg)
{
    struct pool* pool = (struct pool*)arg;

    if (pool_active(pool, false))
    {
        pool_tset(pool, &pool->lagging);
        pool_tclear(pool, &pool->idle);

        cg_wlock(&control_lock);
        if (!pools_active)
        {
            currentpool = pool;
            if (pool->pool_no != 0)
                applog(LOG_NOTICE, "Switching to pool %d %s - first alive pool", pool->pool_no, pool->rpc_url);
            pools_active = true;
        }
        cg_wunlock(&control_lock);
        pool_resus(pool);
    }
    else
        pool_died(pool);

    return NULL;
}

/* Always returns true that the pool details were added unless we are not
 * live, implying this is the only pool being added, so if no pools are
 * active it returns false. */
bool add_pool_details(struct pool* pool, bool live, char* url, char* user, char* pass)
{
    url = get_proxy(url, pool);

    pool->rpc_url = url;
    pool->rpc_user = user;
    pool->rpc_pass = pass;
    pool->rpc_userpass = malloc(strlen(pool->rpc_user) + strlen(pool->rpc_pass) + 2);
    if (!pool->rpc_userpass)
    {
        nxquit(1, "Failed to malloc userpass");
    }
    sprintf(pool->rpc_userpass, "%s:%s", pool->rpc_user, pool->rpc_pass);

    pool->testing = true;
    pool->idle = true;
    enable_pool(pool);

    pthread_create(&pool->test_thread, NULL, test_pool_thread, (void*)pool);
    if (!live)
    {
        pthread_join(pool->test_thread, NULL);
        pool->testing = false;
        return pools_active;
    }
    return true;
}

#ifdef HAVE_CURSES
static bool input_pool(bool live)
{
    char *url = NULL, *user = NULL, *pass = NULL;
    struct pool* pool;
    bool ret = false;

    immedok(logwin, true);
    wlogprint("Input server details.\n");

    url = curses_input("URL");
    if (!url)
        goto out;

    user = curses_input("Username");
    if (!user)
        goto out;

    pass = curses_input("Password");
    if (!pass)
        goto out;

    if (!detect_stratum(pool, url) && strncmp(url, "http://", 7) && strncmp(url, "https://", 8))
    {
        char* httpinput;
        httpinput = malloc(256);
        if (!httpinput)
            nxquit(1, "Failed to malloc httpinput");
        strcpy(httpinput, "http://");
        strncat(httpinput, url, 248);
        free(url);
        url = httpinput;
    }

    ret = add_pool_details(pool, live, url, user, pass);
out:
    immedok(logwin, false);

    if (!ret)
    {
        if (url)
            free(url);
        if (user)
            free(user);
        if (pass)
            free(pass);
    }
    return ret;
}
#endif

#if defined(unix)
static void fork_monitor()
{
    // Make a pipe: [readFD, writeFD]
    int pfd[2];
    int r = pipe(pfd);

    if (r < 0)
    {
        perror("pipe - failed to create pipe for --monitor");
        exit(1);
    }

    // Make stderr write end of pipe
    fflush(stderr);
    r = dup2(pfd[1], 2);
    if (r < 0)
    {
        perror("dup2 - failed to alias stderr to write end of pipe for --monitor");
        exit(1);
    }
    r = close(pfd[1]);
    if (r < 0)
    {
        perror("close - failed to close write end of pipe for --monitor");
        exit(1);
    }

    // Don't allow a dying monitor to kill the main process
    sighandler_t sr0 = signal(SIGPIPE, SIG_IGN);
    sighandler_t sr1 = signal(SIGPIPE, SIG_IGN);
    if (SIG_ERR == sr0 || SIG_ERR == sr1)
    {
        perror("signal - failed to edit signal mask for --monitor");
        exit(1);
    }

    // Fork a child process
    forkpid = fork();
    if (forkpid < 0)
    {
        perror("fork - failed to fork child process for --monitor");
        exit(1);
    }

    // Child: launch monitor command
    if (0 == forkpid)
    {
        // Make stdin read end of pipe
        r = dup2(pfd[0], 0);
        if (r < 0)
        {
            perror("dup2 - in child, failed to alias read end of pipe to stdin for --monitor");
            exit(1);
        }
        close(pfd[0]);
        if (r < 0)
        {
            perror("close - in child, failed to close read end of  pipe for --monitor");
            exit(1);
        }

        // Launch user specified command
        execl("/bin/bash", "/bin/bash", "-c", opt_stderr_cmd, (char*)NULL);
        perror("execl - in child failed to exec user specified command for --monitor");
        exit(1);
    }

    // Parent: clean up unused fds and bail
    r = close(pfd[0]);
    if (r < 0)
    {
        perror("close - failed to close read end of pipe for --monitor");
        exit(1);
    }
}
#endif // defined(unix)

#ifdef HAVE_CURSES
void enable_curses(void)
{
    int x, y;

    lock_curses();
    if (curses_active)
    {
        unlock_curses();
        return;
    }

    mainwin = initscr();
    getmaxyx(mainwin, y, x);
    statuswin = newwin(logstart, x, 0, 0);
    leaveok(statuswin, true);
    logwin = newwin(y - logcursor, 0, logcursor, 0);
    idlok(logwin, true);
    scrollok(logwin, true);
    leaveok(logwin, true);
    cbreak();
    noecho();
    curses_active = true;
    statusy = logstart;
    unlock_curses();
}
#endif

/* TODO: fix need a dummy CPU device_drv even if no support for CPU mining */
#ifndef WANT_CPUMINE
struct device_drv cpu_drv;
struct device_drv cpu_drv = {
    .drv_id = DRIVER_CPU,
    .name = "CPU",
};
#endif

static int cgminer_id_count = 0;

/* Various noop functions for drivers that don't support or need their
 * variants. */
static void noop_reinit_device(struct cgpu_info __maybe_unused* cgpu) {}

void blank_get_statline_before(char* buf, struct cgpu_info __maybe_unused* cgpu)
{
    tailsprintf(buf, "               | ");
}

static void noop_get_statline(char __maybe_unused* buf, struct cgpu_info __maybe_unused* cgpu) {}

static bool noop_get_stats(struct cgpu_info __maybe_unused* cgpu)
{
    return true;
}

static bool noop_thread_prepare(struct thr_info __maybe_unused* thr)
{
    return true;
}

static void noop_can_limit_work(struct thr_info __maybe_unused* thr)
{
    // intentionally do nothing
}

static bool noop_thread_init(struct thr_info __maybe_unused* thr)
{
    return true;
}

static bool noop_prepare_work(struct thr_info __maybe_unused* thr, struct work __maybe_unused* work)
{
    return true;
}

static void noop_hw_error(struct thr_info __maybe_unused* thr) {}

static void noop_thread_shutdown(struct thr_info __maybe_unused* thr) {}

static void noop_thread_enable(struct thr_info __maybe_unused* thr) {}

#define noop_flush_work noop_reinit_device
#define noop_queue_full noop_get_stats

/* Fill missing driver drv functions with noops */
void fill_device_drv(struct cgpu_info* cgpu)
{
    struct device_drv* drv = cgpu->drv;

    if (!drv->reinit_device)
        drv->reinit_device = &noop_reinit_device;
    if (!drv->get_statline_before)
        drv->get_statline_before = &blank_get_statline_before;
    if (!drv->get_statline)
        drv->get_statline = &noop_get_statline;
    if (!drv->get_stats)
        drv->get_stats = &noop_get_stats;
    if (!drv->thread_prepare)
        drv->thread_prepare = &noop_thread_prepare;
    if (!drv->can_limit_work)
        drv->can_limit_work = &noop_can_limit_work;
    if (!drv->thread_init)
        drv->thread_init = &noop_thread_init;
    if (!drv->prepare_work)
        drv->prepare_work = &noop_prepare_work;
    if (!drv->hw_error)
        drv->hw_error = &noop_hw_error;
    if (!drv->thread_shutdown)
        drv->thread_shutdown = &noop_thread_shutdown;
    if (!drv->thread_enable)
        drv->thread_enable = &noop_thread_enable;
    if (!drv->hash_work)
        drv->hash_work = &hash_sole_work;
    if (!drv->flush_work)
        drv->flush_work = &noop_flush_work;
    if (!drv->queue_full)
        drv->queue_full = &noop_queue_full;
    if (!drv->max_diff)
        drv->max_diff = 1;
}

void enable_device(struct cgpu_info* cgpu)
{
    cgpu->deven = DEV_ENABLED;
    wr_lock(&devices_lock);
    devices[cgpu->cgminer_id = cgminer_id_count++] = cgpu;
    wr_unlock(&devices_lock);
    if (hotplug_mode)
    {
        new_threads += cgpu->threads;
#ifdef HAVE_CURSES
        adj_width(mining_threads + new_threads, &dev_width);
#endif
    }
    else
    {
        mining_threads += cgpu->threads;
#ifdef HAVE_CURSES
        adj_width(mining_threads, &dev_width);
#endif
    }
#ifdef HAVE_OPENCL
    if (cgpu->drv->drv_id == DRIVER_OPENCL)
    {
        gpu_threads += cgpu->threads;
    }
#endif
    fill_device_drv(cgpu);

    rwlock_init(&cgpu->qlock);
    cgpu->queued_work = NULL;
}

struct _cgpu_devid_counter
{
    char name[4];
    int lastid;
    UT_hash_handle hh;
};

bool add_cgpu(struct cgpu_info* cgpu)
{
    static struct _cgpu_devid_counter* devids = NULL;
    struct _cgpu_devid_counter* d;

    HASH_FIND_STR(devids, cgpu->drv->name, d);
    if (d)
        cgpu->device_id = ++d->lastid;
    else
    {
        d = malloc(sizeof(*d));
        memcpy(d->name, cgpu->drv->name, sizeof(d->name));
        cgpu->device_id = d->lastid = 0;
        HASH_ADD_STR(devids, name, d);
    }
    wr_lock(&devices_lock);
    devices = realloc(devices, sizeof(struct cgpu_info*) * (total_devices + new_devices + 2));
    wr_unlock(&devices_lock);
    if (hotplug_mode)
        devices[total_devices + new_devices++] = cgpu;
    else
        devices[total_devices++] = cgpu;
    return true;
}

struct device_drv* copy_drv(struct device_drv* drv)
{
    struct device_drv* copy;
    char buf[100];

    if (unlikely(!(copy = malloc(sizeof(*copy)))))
    {
        sprintf(buf, "Failed to allocate device_drv copy of %s (%s)", drv->name, drv->copy ? "copy" : "original");
        nxquit(1, buf);
    }
    memcpy(copy, drv, sizeof(*copy));
    copy->copy = true;
    return copy;
}

static void probe_pools(void)
{
    int i;

    for (i = 0; i < total_pools; i++)
    {
        struct pool* pool = pools[i];

        pool->testing = true;
        pthread_create(&pool->test_thread, NULL, test_pool_thread, (void*)pool);
    }
}

static void GetRandBytes(unsigned char* buf, int num)
{
    if (RAND_bytes(buf, num) != 1)
    {
        assert("Failed to read randomness, aborting");
    }
}

static void ECC_Start()
{
    assert(secp256k1_context_sign == NULL);

    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    assert(ctx != NULL);

    {
        // Pass in a random blinding seed to the secp256k1 context.
        unsigned char seed[32];
        GetRandBytes(seed, 32);
        bool ret = secp256k1_context_randomize(ctx, seed);
        assert(ret);
    }

    secp256k1_context_sign = ctx;
}

int main(int argc, char* argv[])
{
    ECC_Start();

    struct sigaction handler;
    struct thr_info* thr;
    struct block* block;
    unsigned int k;
    int i, j;
    char* s;

    /* This dangerous functions tramples random dynamically allocated
     * variables so do it before anything at all */
    if (unlikely(curl_global_init(CURL_GLOBAL_ALL)))
        nxquit(1, "Failed to curl_global_init");

    initial_args = malloc(sizeof(char*) * (argc + 1));
    for (i = 0; i < argc; i++)
        initial_args[i] = strdup(argv[i]);
    initial_args[argc] = NULL;

    mutex_init(&hash_lock);
    mutex_init(&console_lock);
    cglock_init(&control_lock);
    mutex_init(&stats_lock);
    mutex_init(&sharelog_lock);
    cglock_init(&ch_lock);
    mutex_init(&sshare_lock);
    rwlock_init(&blk_lock);
    rwlock_init(&netacc_lock);
    rwlock_init(&mining_thr_lock);
    rwlock_init(&devices_lock);

    mutex_init(&lp_lock);
    if (unlikely(pthread_cond_init(&lp_cond, NULL)))
        nxquit(1, "Failed to pthread_cond_init lp_cond");

    mutex_init(&restart_lock);
    if (unlikely(pthread_cond_init(&restart_cond, NULL)))
        nxquit(1, "Failed to pthread_cond_init restart_cond");

    if (unlikely(pthread_cond_init(&gws_cond, NULL)))
        nxquit(1, "Failed to pthread_cond_init gws_cond");

    sprintf(packagename, "%s %s", PACKAGE_NAME, PACKAGE_VERSION);
    printf(packagename, "%s %s", PACKAGE_NAME, PACKAGE_VERSION);

#ifdef WANT_CPUMINE
    init_max_name_len();
#endif

    handler.sa_handler = &sighandler;
    handler.sa_flags = 0;
    sigemptyset(&handler.sa_mask);
    sigaction(SIGTERM, &handler, &termhandler);
    sigaction(SIGINT, &handler, &inthandler);
#ifndef WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    opt_kernel_path = alloca(PATH_MAX);
    strcpy(opt_kernel_path, NXMINER_PREFIX);
    cgminer_path = alloca(PATH_MAX);
    s = strdup(argv[0]);
    strcpy(cgminer_path, dirname(s));
    free(s);
    strcat(cgminer_path, "/");
#ifdef WANT_CPUMINE
    // Hack to make cgminer silent when called recursively on WIN32
    int skip_to_bench = 0;
#if defined(WIN32)
    char buf[32];
    if (GetEnvironmentVariable("CGMINER_BENCH_ALGO", buf, 16))
        skip_to_bench = 1;
#endif // defined(WIN32)
#endif

    devcursor = 8;
    logstart = devcursor + 1;
    logcursor = logstart + 1;

    block = calloc(sizeof(struct block), 1);
    if (unlikely(!block))
    {
        nxquit(1, "main OOM");
    }
    memset(block->commitment_hex, 0, 64);
    block->commitment_hex[64] = '\0';
    HASH_ADD_STR(blocks, commitment_hex, block);
    memcpy(current_block, block->commitment_hex, 65);

    INIT_LIST_HEAD(&scan_devices);

#ifdef HAVE_OPENCL
    memset(gpus, 0, sizeof(gpus));
    for (i = 0; i < MAX_GPUDEVICES; i++)
        gpus[i].dynamic = true;
#endif

    /* parse command line */
    opt_register_table(opt_config_table, "Options for both config file and command line");
    opt_register_table(opt_cmdline_table, "Options for command line only");

    opt_parse(&argc, argv, applog_and_exit);
    if (argc != 1)
        nxquit(1, "Unexpected extra commandline arguments");

    if (!config_loaded)
        load_default_config();

    if (opt_benchmark)
    {
        struct pool* pool;

        pool = add_pool();
        pool->rpc_url = malloc(255);
        strcpy(pool->rpc_url, "Benchmark");
        pool->rpc_user = pool->rpc_url;
        pool->rpc_pass = pool->rpc_url;
        enable_pool(pool);
        pool->idle = false;
        successful_connect = true;
    }

#ifdef HAVE_CURSES
    if (opt_realquiet || devices_enabled == -1)
        use_curses = false;

    if (use_curses)
        enable_curses();
#endif

    applog(LOG_WARNING, "Started %s", packagename);
    if (cnfbuf)
    {
        applog(LOG_NOTICE, "Loaded configuration file %s", cnfbuf);
        switch (fileconf_load)
        {
        case 0:
            applog(LOG_WARNING, "Fatal JSON error in configuration file.");
            applog(LOG_WARNING, "Configuration file could not be used.");
            break;
        case -1:
            applog(LOG_WARNING, "Error in configuration file, partially loaded.");
            if (use_curses)
                applog(LOG_WARNING, "Start cgminer with -T to see what failed to load.");
            break;
        default:
            break;
        }
        free(cnfbuf);
        cnfbuf = NULL;
    }

    strcat(opt_kernel_path, "/");

    if (want_per_device_stats)
        opt_log_output = true;

#ifdef WANT_CPUMINE
    if (0 <= opt_bench_algo)
    {
        double rate = bench_algo_stage3(opt_bench_algo);

        if (!skip_to_bench)
            printf("%.5f (%s)\n", rate, algo_names[opt_bench_algo]);
        else
        {
            // Write result to shared memory for parent
#if defined(WIN32)
            char unique_name[64];

            if (GetEnvironmentVariable("CGMINER_SHARED_MEM", unique_name, 32))
            {
                HANDLE map_handle = CreateFileMapping(INVALID_HANDLE_VALUE, // use paging file
                    NULL, // default security attributes
                    PAGE_READWRITE, // read/write access
                    0, // size: high 32-bits
                    4096, // size: low 32-bits
                    unique_name // name of map object
                );
                if (NULL != map_handle)
                {
                    void* shared_mem = MapViewOfFile(map_handle, // object to map view of
                        FILE_MAP_WRITE, // read/write access
                        0, // high offset:  map from
                        0, // low offset:   beginning
                        0 // default: map entire file
                    );
                    if (NULL != shared_mem)
                        CopyMemory(shared_mem, &rate, sizeof(rate));
                    (void)UnmapViewOfFile(shared_mem);
                }
                (void)CloseHandle(map_handle);
            }
#endif
        }
        exit(0);
    }
#endif

#ifdef HAVE_OPENCL
    if (!opt_nogpu)
        opencl_drv.drv_detect();
    gpu_threads = 0;
#endif

#ifdef WANT_CPUMINE
    cpu_drv.drv_detect();
#endif

    if (devices_enabled == -1)
    {
        applog(LOG_ERR, "Devices detected:");
        for (i = 0; i < total_devices; ++i)
        {
            struct cgpu_info* cgpu = devices[i];
            if (cgpu->name)
            {
                applog(LOG_ERR, " %2d. %s %d: %s (driver: %s)", i, cgpu->drv->name, cgpu->device_id, cgpu->name,
                    cgpu->drv->dname);
            }
            else
            {
                applog(LOG_ERR, " %2d. %s %d (driver: %s)", i, cgpu->drv->name, cgpu->device_id, cgpu->drv->dname);
            }
        }
        nxquit(0, "%d devices listed", total_devices);
    }

    mining_threads = 0;
    if (devices_enabled)
    {
        for (i = 0; i < (int)(sizeof(devices_enabled) * 8) - 1; ++i)
        {
            if (devices_enabled & (1 << i))
            {
                if (i >= total_devices)
                {
                    nxquit(1, "Command line options set a device that doesn't exist");
                }
                enable_device(devices[i]);
            }
            else if (i < total_devices)
            {
                if (opt_removedisabled)
                {
                    if (devices[i]->drv->drv_id == DRIVER_CPU)
                    {
                        --opt_n_threads;
                    }
                }
                else
                {
                    enable_device(devices[i]);
                }
                devices[i]->deven = DEV_DISABLED;
            }
        }
        total_devices = cgminer_id_count;
    }
    else
    {
        for (i = 0; i < total_devices; ++i)
        {
            enable_device(devices[i]);
        }
    }

    if (!total_devices)
        nxquit(1, "All devices disabled, cannot mine!");

    start_devices = total_devices;

    load_temp_cutoffs();

    for (i = 0; i < total_devices; ++i)
        devices[i]->cgminer_stats.getwork_wait_min.tv_sec = MIN_SEC_UNSET;

    if (!opt_compact)
    {
        logstart += total_devices;
        logcursor = logstart + 1;
#ifdef HAVE_CURSES
        check_winsizes();
#endif
    }

    if (!total_pools)
    {
        applog(LOG_WARNING, "Need to specify at least one pool server.");
#ifdef HAVE_CURSES
        if (!use_curses || !input_pool(false))
#endif
            nxquit(1, "Pool setup failed");
    }

    for (i = 0; i < total_pools; i++)
    {
        struct pool* pool = pools[i];

        pool->cgminer_stats.getwork_wait_min.tv_sec = MIN_SEC_UNSET;
        pool->cgminer_pool_stats.getwork_wait_min.tv_sec = MIN_SEC_UNSET;

        if (!pool->rpc_userpass)
        {
            if (!pool->rpc_user || !pool->rpc_pass)
            {
                nxquit(1, "No login credentials supplied for pool %u %s", i, pool->rpc_url);
            }
            pool->rpc_userpass = malloc(strlen(pool->rpc_user) + strlen(pool->rpc_pass) + 2);
            if (!pool->rpc_userpass)
            {
                nxquit(1, "Failed to malloc userpass");
            }
            sprintf(pool->rpc_userpass, "%s:%s", pool->rpc_user, pool->rpc_pass);
        }
    }
    /* Set the currentpool to pool 0 */
    currentpool = pools[0];

#ifdef HAVE_SYSLOG_H
    if (use_syslog)
        openlog(PACKAGE_NAME, LOG_PID, LOG_USER);
#endif

#if defined(unix)
    if (opt_stderr_cmd)
    {
        fork_monitor();
    }
#endif // defined(unix)

    mining_thr = calloc(mining_threads, sizeof(thr));
    if (!mining_thr)
        nxquit(1, "Failed to calloc mining_thr");
    for (i = 0; i < mining_threads; i++)
    {
        mining_thr[i] = calloc(1, sizeof(*thr));
        if (!mining_thr[i])
            nxquit(1, "Failed to calloc mining_thr[%d]", i);
    }

    total_control_threads = 8;
    control_thr = calloc(total_control_threads, sizeof(*thr));
    if (!control_thr)
        nxquit(1, "Failed to calloc control_thr");

    gwsched_thr_id = 0;
    stage_thr_id = 1;
    thr = &control_thr[stage_thr_id];
    thr->q = tq_new();
    if (!thr->q)
        nxquit(1, "Failed to tq_new");
    /* start stage thread */
    if (thr_info_create(thr, NULL, stage_thread, thr))
        nxquit(1, "stage thread create failed");
    pthread_detach(thr->pth);

    /* Create a unique get work queue */
    getq = tq_new();
    if (!getq)
    {
        nxquit(1, "Failed to create getq");
    }
    /* We use the getq mutex as the staged lock */
    stgd_lock = &getq->mutex;

    if (opt_benchmark)
    {
        goto begin_bench;
    }

    for (i = 0; i < total_pools; i++)
    {
        struct pool* pool = pools[i];

        enable_pool(pool);
        pool->idle = true;
    }

    applog(LOG_NOTICE, "Probing for an alive pool");
    do
    {
        int slept = 0;

        /* Look for at least one active pool before starting */
        probe_pools();
        do
        {
            sleep(1);
            slept++;
        } while (!pools_active && slept < 60);

        if (!pools_active)
        {
            applog(LOG_ERR, "No servers were found that could be used to get work from.");
            applog(LOG_ERR, "Please check the details from the list below of the servers you have input");
            applog(LOG_ERR, "Most likely you have input the wrong URL, forgotten to add a port, or have "
                            "not set up workers");
            for (i = 0; i < total_pools; i++)
            {
                struct pool* pool;

                pool = pools[i];
                applog(LOG_WARNING, "Pool: %d  URL: %s  User: %s  Password: %s", i, pool->rpc_url, pool->rpc_user,
                    pool->rpc_pass);
            }
#ifdef HAVE_CURSES
            if (use_curses)
            {
                halfdelay(150);
                applog(LOG_ERR, "Press any key to exit, or cgminer will try again in 15s.");
                if (getch() != ERR)
                    nxquit(0, "No servers could be used! Exiting.");
                cbreak();
            }
            else
#endif
                nxquit(0, "No servers could be used! Exiting.");
        }
    } while (!pools_active);

begin_bench:
    total_mhashes_done = 0;
    for (i = 0; i < total_devices; i++)
    {
        struct cgpu_info* cgpu = devices[i];

        cgpu->rolling = cgpu->total_mhashes = 0;
    }

    gettimeofday(&total_tv_start, NULL);
    gettimeofday(&total_tv_end, NULL);
    get_datestamp(datestamp, &total_tv_start);

    // Start threads
    k = 0;
    for (i = 0; i < total_devices; ++i)
    {
        struct cgpu_info* cgpu = devices[i];
        cgpu->thr = malloc(sizeof(*cgpu->thr) * (cgpu->threads + 1));
        cgpu->thr[cgpu->threads] = NULL;
        cgpu->status = LIFE_INIT;

        for (j = 0; j < cgpu->threads; ++j, ++k)
        {
            thr = get_thread(k);
            thr->id = k;
            thr->cgpu = cgpu;
            thr->device_thread = j;
            memset(thr->lastCommitment, 0, 32);
            memset(thr->thread_nonce, 0, 16);

            thr->q = tq_new();
            if (!thr->q)
                nxquit(1, "tq_new failed in starting %s%d mining thread (#%d)", cgpu->drv->name, cgpu->device_id, i);

            /* Enable threads for devices set not to mine but disable
             * their queue in case we wish to enable them later */
            if (cgpu->deven != DEV_DISABLED)
            {
                applog(LOG_DEBUG, "Pushing ping to thread %d", thr->id);

                tq_push(thr->q, &ping);
            }

            if (!cgpu->drv->thread_prepare(thr))
                continue;

            thread_reportout(thr);

            if (unlikely(thr_info_create(thr, NULL, miner_thread, thr)))
                nxquit(1, "thread %d create failed", thr->id);

            cgpu->thr[j] = thr;
        }
    }

#ifdef HAVE_OPENCL
    applog(LOG_INFO, "%d gpu miner threads started", gpu_threads);
    for (i = 0; i < nDevs; i++)
        pause_dynamic_threads(i);
#endif

#ifdef WANT_CPUMINE
    applog(LOG_INFO,
        "%d cpu miner threads started, "
        "using SHA256 '%s' algorithm.",
        opt_n_threads, algo_names[opt_algo]);
#endif

    gettimeofday(&total_tv_start, NULL);
    gettimeofday(&total_tv_end, NULL);

    watchpool_thr_id = 2;
    thr = &control_thr[watchpool_thr_id];
    /* start watchpool thread */
    if (thr_info_create(thr, NULL, watchpool_thread, NULL))
        nxquit(1, "watchpool thread create failed");
    pthread_detach(thr->pth);

    watchdog_thr_id = 3;
    thr = &control_thr[watchdog_thr_id];
    /* start watchdog thread */
    if (thr_info_create(thr, NULL, watchdog_thread, NULL))
        nxquit(1, "watchdog thread create failed");
    pthread_detach(thr->pth);

#ifdef HAVE_OPENCL
    /* Create reinit gpu thread */
    gpur_thr_id = 4;
    thr = &control_thr[gpur_thr_id];
    thr->q = tq_new();
    if (!thr->q)
        nxquit(1, "tq_new failed for gpur_thr_id");
    if (thr_info_create(thr, NULL, reinit_gpu, thr))
        nxquit(1, "reinit_gpu thread create failed");
#endif

    /* Create API socket thread */
    api_thr_id = 5;
    thr = &control_thr[api_thr_id];
    if (thr_info_create(thr, NULL, api_thread, thr))
        nxquit(1, "API thread create failed");

#ifdef HAVE_CURSES
    /* Create curses input thread for keyboard input. Create this last so
     * that we know all threads are created since this can call kill_work
     * to try and shut down all previous threads. */
    input_thr_id = 7;
    thr = &control_thr[input_thr_id];
    if (thr_info_create(thr, NULL, input_thread, thr))
        nxquit(1, "input thread create failed");
    pthread_detach(thr->pth);
#endif

    /* Just to be sure */
    if (total_control_threads != 8)
        nxquit(1, "incorrect total_control_threads (%d) should be 8", total_control_threads);

    /* Once everything is set up, main() becomes the getwork scheduler */
    while (42)
    {
        int ts, max_staged = opt_queue;
        struct pool *pool, *cp;
        bool lagging = false;
        struct curl_ent* ce;
        struct work* work;

        cp = current_pool();

        /* If the primary pool is a getwork pool and cannot roll work,
         * try to stage one extra work per mining thread */
        if (!cp->has_stratum && !staged_rollable)
            max_staged += mining_threads;

        mutex_lock(stgd_lock);
        ts = __total_staged();

        if (!cp->has_stratum && !ts && !opt_fail_only)
            lagging = true;

        /* Wait until hash_pop tells us we need to create more work */
        if (ts > max_staged)
        {
            pthread_cond_wait(&gws_cond, stgd_lock);
            ts = __total_staged();
        }
        mutex_unlock(stgd_lock);

        if (ts > max_staged)
            continue;

        work = make_work();

        if (lagging && !pool_tset(cp, &cp->lagging))
        {
            applog(LOG_WARNING, "Pool %d not providing work fast enough", cp->pool_no);
            cp->getfail_occasions++;
            total_go++;
        }
        pool = select_pool(lagging);
    retry:
        if (pool->has_stratum)
        {
            while (!pool->stratum_active || !pool->stratum_notify)
            {
                struct pool* altpool = select_pool(true);

                nmsleep(5000);
                if (altpool != pool)
                {
                    pool = altpool;
                    goto retry;
                }
            }
            gen_stratum_work(pool, work);
            applog(LOG_DEBUG, "Generated stratum work");
            stage_work(work);
            continue;
        }

        if (opt_benchmark)
        {
            get_benchmark_work(work);
            applog(LOG_DEBUG, "Generated benchmark work");
            stage_work(work);
            continue;
        }
        work->pool = pool;
    }

    return 0;
}
