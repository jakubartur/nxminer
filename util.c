/*
 * Copyright 2011-2013 Con Kolivas
 * Copyright 2010 Jeff Garzik
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <jansson.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#ifndef WIN32
#ifdef __linux
#include <sys/prctl.h>
#endif
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include "compat.h"
#include "elist.h"
#include "miner.h"
#include "util.h"

bool successful_connect = false;
struct timeval nettime;

struct tq_ent
{
    void* data;
    struct list_head q_node;
};

static void keep_curlalive(CURL* curl)
{
    const int tcp_keepidle = 45;
    const int tcp_keepintvl = 30;
    const long int keepalive = 1;

    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, keepalive);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, tcp_keepidle);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, tcp_keepintvl);
}

static void keep_alive(CURL* curl, __maybe_unused SOCKETTYPE fd)
{
    keep_curlalive(curl);
}

static void last_nettime(struct timeval* last)
{
    rd_lock(&netacc_lock);
    last->tv_sec = nettime.tv_sec;
    last->tv_usec = nettime.tv_usec;
    rd_unlock(&netacc_lock);
}

static void set_nettime(void)
{
    wr_lock(&netacc_lock);
    gettimeofday(&nettime, NULL);
    wr_unlock(&netacc_lock);
}

static int curl_debug_cb(__maybe_unused CURL* handle,
    curl_infotype type,
    __maybe_unused char* data,
    size_t size,
    void* userdata)
{
    struct pool* pool = (struct pool*)userdata;

    switch (type)
    {
    case CURLINFO_HEADER_IN:
    case CURLINFO_DATA_IN:
    case CURLINFO_SSL_DATA_IN:
        pool->cgminer_pool_stats.net_bytes_received += size;
        break;
    case CURLINFO_HEADER_OUT:
    case CURLINFO_DATA_OUT:
    case CURLINFO_SSL_DATA_OUT:
        pool->cgminer_pool_stats.net_bytes_sent += size;
        break;
    case CURLINFO_TEXT:
    default:
        break;
    }
    return 0;
}

static struct
{
    const char* name;
    curl_proxytype proxytype;
} proxynames[] = {{"http:", CURLPROXY_HTTP},
    {"http0:", CURLPROXY_HTTP_1_0},
    (LIBCURL_VERSION_MINOR == 15 && LIBCURL_VERSION_PATCH >= 2)
    {"socks4:", CURLPROXY_SOCKS4},
    {"socks5:", CURLPROXY_SOCKS5},
    {"socks4a:", CURLPROXY_SOCKS4A}, {"socks5h:", CURLPROXY_SOCKS5_HOSTNAME},
    {NULL, 0}};

const char* proxytype(curl_proxytype proxytype)
{
    int i;

    for (i = 0; proxynames[i].name; i++)
        if (proxynames[i].proxytype == proxytype)
            return proxynames[i].name;

    return "invalid";
}

char* get_proxy(char* url, struct pool* pool)
{
    pool->rpc_proxy = NULL;
    char* split;
    int plen, len, i;

    for (i = 0; proxynames[i].name; i++)
    {
        plen = strlen(proxynames[i].name);
        if (strncmp(url, proxynames[i].name, plen) == 0)
        {
            if (!(split = strchr(url, '|')))
                return url;

            *split = '\0';
            len = split - url;
            pool->rpc_proxy = malloc(1 + len - plen);
            if (!(pool->rpc_proxy))
                nxquit(1, "Failed to malloc rpc_proxy");

            strcpy(pool->rpc_proxy, url + plen);
            pool->rpc_proxytype = proxynames[i].proxytype;
            url = split + 1;
            break;
        }
    }
    return url;
}

/* Returns a malloced array string of a binary value of arbitrary length. The
 * array is rounded up to a 4 byte size to appease architectures that need
 * aligned array  sizes */
char* bin2hex(const unsigned char* p, size_t len)
{
    unsigned int i;
    ssize_t slen;
    char* s;

    slen = len * 2 + 1;
    if (slen % 4)
    {
        slen += 4 - (slen % 4);
    }
    s = calloc(slen, 1);
    if (unlikely(!s))
    {
        nxquit(1, "Failed to calloc in bin2hex");
    }

    for (i = 0; i < len; i++)
    {
        sprintf(s + (i * 2), "%02x", (unsigned int)p[i]);
    }
    return s;
}

/* Does the reverse of bin2hex but does not allocate any ram */
bool hex2bin(unsigned char* p, const char* hexstr, size_t len)
{
    bool ret = false;

    while (*hexstr && len)
    {
        char hex_byte[4];
        unsigned int v;

        if (unlikely(!hexstr[1]))
        {
            applog(LOG_ERR, "hex2bin str truncated");
            return ret;
        }

        memset(hex_byte, 0, 4);
        hex_byte[0] = hexstr[0];
        hex_byte[1] = hexstr[1];

        if (unlikely(sscanf(hex_byte, "%x", &v) != 1))
        {
            applog(LOG_ERR, "hex2bin sscanf '%s' failed", hex_byte);
            return ret;
        }

        *p = (unsigned char)v;

        p++;
        hexstr += 2;
        len--;
    }

    if (likely(len == 0 && *hexstr == 0))
        ret = true;
    return ret;
}

// returns the uint256 target for a given difficulty
// difficulty_target = maximum_target / difficulty

void difficulty_to_target(double difficulty, uint8_t* res)
{
    memcpy(res, UINT256_ZERO, 32);
    uint8_t difficulty_uint256[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    // multiply for precision
    double dShifted_diff = difficulty * 100000000;
    // truncate remaining decimal places
    uint64_t nShifted_diff = (uint64_t) dShifted_diff;
    uint8_t divisor[32] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    uint64_to_uint256(nShifted_diff, divisor);
    if (uint256_divide(UINT256_DIFF1, divisor, difficulty_uint256) == false)
    {
        // can not divide, return diff 1 as a default target
        memcpy(res, UINT256_DIFF1, 32);
        return;
    }
    // multiply by 1000 because the shifted diff was multiplied by 1000
    uint256_multiply(difficulty_uint256, UINT256_100000000, res);
}

double nbits_to_difficulty(const uint32_t* nBits)
{
    int32_t nShift = (*nBits >> 24) & 0xff;
    double difficulty = (double)0x0000ffff / (double)(*nBits & 0x00ffffff);
    while (nShift < 29)
    {
        difficulty *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        difficulty /= 256.0;
        nShift--;
    }
    return difficulty;
}

bool fulltest(const unsigned char* hash, const unsigned char* target)
{
    unsigned char hash_swap[32];
    unsigned char target_swap[32];
    int i;
    // reverse the hashes for comparison
    for (i = 0; i < 32; ++i)
    {
        hash_swap[i] = hash[31 - i];
        target_swap[i] = target[31 - i];
    }
    bool rc = (memcmp(hash_swap, target_swap, 32) < 0);
    if (opt_debug)
    {
        char* hash_str;
        hash_str = bin2hex(hash_swap, 32);
        char* target_str;
        target_str = bin2hex(target_swap, 32);
        if (rc)
        {
            applog(LOG_DEBUG, " Proof: %s\nTarget: %s\nTrgVal? %s", hash_str, target_str, rc ? "YES (hash < target)" : "no (false positive; hash > target)");
        }
        free(hash_str);
        free(target_str);
    }
    return rc;
}

struct thread_q* tq_new(void)
{
    struct thread_q* tq;

    tq = calloc(1, sizeof(*tq));
    if (!tq)
        return NULL;

    INIT_LIST_HEAD(&tq->q);
    pthread_mutex_init(&tq->mutex, NULL);
    pthread_cond_init(&tq->cond, NULL);

    return tq;
}

void tq_free(struct thread_q* tq)
{
    struct tq_ent *ent, *iter;

    if (!tq)
        return;

    list_for_each_entry_safe(ent, iter, &tq->q, q_node)
    {
        list_del(&ent->q_node);
        free(ent);
    }

    pthread_cond_destroy(&tq->cond);
    pthread_mutex_destroy(&tq->mutex);

    memset(tq, 0, sizeof(*tq)); /* poison */
    free(tq);
}

static void tq_freezethaw(struct thread_q* tq, bool frozen)
{
    mutex_lock(&tq->mutex);

    tq->frozen = frozen;

    pthread_cond_signal(&tq->cond);
    mutex_unlock(&tq->mutex);
}

void tq_freeze(struct thread_q* tq)
{
    tq_freezethaw(tq, true);
}

void tq_thaw(struct thread_q* tq)
{
    tq_freezethaw(tq, false);
}

bool tq_push(struct thread_q* tq, void* data)
{
    struct tq_ent* ent;
    bool rc = true;

    ent = calloc(1, sizeof(*ent));
    if (!ent)
        return false;

    ent->data = data;
    INIT_LIST_HEAD(&ent->q_node);

    mutex_lock(&tq->mutex);

    if (!tq->frozen)
    {
        list_add_tail(&ent->q_node, &tq->q);
    }
    else
    {
        free(ent);
        rc = false;
    }

    pthread_cond_signal(&tq->cond);
    mutex_unlock(&tq->mutex);

    return rc;
}

void* tq_pop(struct thread_q* tq, const struct timespec* abstime)
{
    struct tq_ent* ent;
    void* rval = NULL;
    int rc;

    mutex_lock(&tq->mutex);

    if (!list_empty(&tq->q))
        goto pop;

    if (abstime)
        rc = pthread_cond_timedwait(&tq->cond, &tq->mutex, abstime);
    else
        rc = pthread_cond_wait(&tq->cond, &tq->mutex);
    if (rc)
        goto out;
    if (list_empty(&tq->q))
        goto out;

pop:
    ent = list_entry(tq->q.next, struct tq_ent, q_node);
    rval = ent->data;

    list_del(&ent->q_node);
    free(ent);

out:
    mutex_unlock(&tq->mutex);
    return rval;
}

int thr_info_create(struct thr_info* thr, pthread_attr_t* attr, void* (*start)(void*), void* arg)
{
    return pthread_create(&thr->pth, attr, start, arg);
}

void thr_info_freeze(struct thr_info* thr)
{
    struct tq_ent *ent, *iter;
    struct thread_q* tq;

    if (!thr)
        return;

    tq = thr->q;
    if (!tq)
        return;

    mutex_lock(&tq->mutex);
    tq->frozen = true;
    list_for_each_entry_safe(ent, iter, &tq->q, q_node)
    {
        list_del(&ent->q_node);
        free(ent);
    }
    mutex_unlock(&tq->mutex);
}

void thr_info_cancel(struct thr_info* thr)
{
    if (!thr)
        return;

    if (PTH(thr) != 0L)
    {
        pthread_cancel(thr->pth);
        PTH(thr) = 0L;
    }
}

/* Provide a ms based sleep that uses nanosleep to avoid poor usleep accuracy
 * on SMP machines */
void nmsleep(unsigned int msecs)
{
    struct timespec twait, tleft;
    int ret;
    ldiv_t d;

    d = ldiv(msecs, 1000);
    tleft.tv_sec = d.quot;
    tleft.tv_nsec = d.rem * 1000000;
    do
    {
        twait.tv_sec = tleft.tv_sec;
        twait.tv_nsec = tleft.tv_nsec;
        ret = nanosleep(&twait, &tleft);
    } while (ret == -1 && errno == EINTR);
}

/* Returns the microseconds difference between end and start times as a double */
double us_tdiff(struct timeval* end, struct timeval* start)
{
    return end->tv_sec * 1000000 + end->tv_usec - start->tv_sec * 1000000 - start->tv_usec;
}

/* Returns the seconds difference between end and start times as a double */
double tdiff(struct timeval* end, struct timeval* start)
{
    return end->tv_sec - start->tv_sec + (end->tv_usec - start->tv_usec) / 1000000.0;
}

bool extract_sockaddr(struct pool* pool, char* url)
{
    char *url_begin, *url_end, *ipv6_begin, *ipv6_end, *port_start = NULL;
    char url_address[256], port[6];
    int url_len, port_len = 0;

    pool->sockaddr_url = url;
    url_begin = strstr(url, "//");
    if (!url_begin)
        url_begin = url;
    else
        url_begin += 2;

    /* Look for numeric ipv6 entries */
    ipv6_begin = strstr(url_begin, "[");
    ipv6_end = strstr(url_begin, "]");
    if (ipv6_begin && ipv6_end && ipv6_end > ipv6_begin)
        url_end = strstr(ipv6_end, ":");
    else
        url_end = strstr(url_begin, ":");
    if (url_end)
    {
        url_len = url_end - url_begin;
        port_len = strlen(url_begin) - url_len - 1;
        if (port_len < 1)
            return false;
        port_start = url_end + 1;
    }
    else
        url_len = strlen(url_begin);

    if (url_len < 1)
        return false;

    sprintf(url_address, "%.*s", url_len, url_begin);

    if (port_len)
        snprintf(port, 6, "%.*s", port_len, port_start);
    else
        strcpy(port, "80");

    pool->echelon_port = strdup(port);
    pool->sockaddr_url = strdup(url_address);

    return true;
}

static bool socket_full(struct pool* pool, bool wait)
{
    SOCKETTYPE sock = pool->sock;
    struct timeval timeout;
    fd_set rd;

    FD_ZERO(&rd);
    FD_SET(sock, &rd);
    timeout.tv_usec = 0;
    if (wait)
        timeout.tv_sec = 60;
    else
        timeout.tv_sec = 0;
    if (select(sock + 1, &rd, NULL, NULL, &timeout) > 0)
        return true;
    return false;
}

/* Check to see if Santa's been good to you */
bool sock_full(struct pool* pool)
{
    if (strlen(pool->sockbuf))
        return true;

    return (socket_full(pool, false));
}

static void clear_sockbuf(struct pool* pool)
{
    strcpy(pool->sockbuf, "");
}

static void clear_sock(struct pool* pool)
{
    ssize_t n;

    mutex_lock(&pool->echelon_lock);
    do
    {
        n = recv(pool->sock, pool->sockbuf, RECVSIZE, 0);
    } while (n > 0);
    mutex_unlock(&pool->echelon_lock);

    clear_sockbuf(pool);
}

/* Make sure the pool sockbuf is large enough to cope with any coinbase size
 * by reallocing it to a large enough size rounded up to a multiple of RBUFSIZE
 * and zeroing the new memory */
static void recalloc_sock(struct pool* pool, size_t len)
{
    size_t old, new;

    old = strlen(pool->sockbuf);
    new = old + len + 1;
    if (new < pool->sockbuf_size)
        return;
    new = new + (RBUFSIZE - (new % RBUFSIZE));
    applog(LOG_DEBUG, "Recallocing pool sockbuf to %lu", new);
    pool->sockbuf = realloc(pool->sockbuf, new);
    if (!pool->sockbuf)
        nxquit(1, "Failed to realloc pool sockbuf in recalloc_sock");
    memset(pool->sockbuf + old, 0, new - old);
    pool->sockbuf_size = new;
}

/* Peeks at a socket to find the first end of line and then reads just that
 * from the socket and returns that as a malloced char */
char* recv_line(struct pool* pool)
{
    ssize_t len, buflen;
    char *tok, *sret = NULL;

    if (!strstr(pool->sockbuf, "\n"))
    {
        struct timeval rstart, now;

        gettimeofday(&rstart, NULL);
        if (!socket_full(pool, true))
        {
            applog(LOG_DEBUG, "Timed out waiting for data on socket_full");
            goto out;
        }

        mutex_lock(&pool->echelon_lock);
        do
        {
            char s[RBUFSIZE];
            size_t slen, n;

            memset(s, 0, RBUFSIZE);
            n = recv(pool->sock, s, RECVSIZE, 0);
            if (n < 1 && errno != EAGAIN && errno != EWOULDBLOCK)
            {
                applog(LOG_DEBUG, "Failed to recv sock in recv_line");
                break;
            }
            slen = strlen(s);
            recalloc_sock(pool, slen);
            strcat(pool->sockbuf, s);
            gettimeofday(&now, NULL);
        } while (tdiff(&now, &rstart) < 60 && !strstr(pool->sockbuf, "\n"));
        mutex_unlock(&pool->echelon_lock);
    }

    buflen = strlen(pool->sockbuf);
    tok = strtok(pool->sockbuf, "\n");
    if (!tok)
    {
        applog(LOG_DEBUG, "Failed to parse a \\n terminated string in recv_line");
        goto out;
    }
    sret = strdup(tok);
    len = strlen(sret);

    /* Copy what's left in the buffer after the \n, including the
     * terminating \0 */
    if (buflen > len + 1)
        memmove(pool->sockbuf, pool->sockbuf + len + 1, buflen - len + 1);
    else
        strcpy(pool->sockbuf, "");

    pool->cgminer_pool_stats.times_received++;
    pool->cgminer_pool_stats.bytes_received += len;
    pool->cgminer_pool_stats.net_bytes_received += len;
out:
    if (!sret)
        clear_sock(pool);
    else if (opt_protocol)
        applog(LOG_DEBUG, "RECVD: %s", sret);
    return sret;
}

/* Extracts a string value from a json array with error checking. To be used
 * when the value of the string returned is only examined and not to be stored.
 * See json_array_string below */
static char* __json_array_string(json_t* val, unsigned int entry)
{
    json_t* arr_entry;

    if (json_is_null(val))
        return NULL;
    if (!json_is_array(val))
        return NULL;
    if (entry > json_array_size(val))
        return NULL;
    arr_entry = json_array_get(val, entry);
    if (!json_is_string(arr_entry))
        return NULL;

    return (char*)json_string_value(arr_entry);
}

/* Creates a freshly malloced dup of __json_array_string */
static char* json_array_string(json_t* val, unsigned int entry)
{
    char* buf = __json_array_string(val, entry);

    if (buf)
        return strdup(buf);
    return NULL;
}

static bool parse_notify(struct pool* pool, json_t* val)
{
    char* job_id;
    char* s_candidateId;
    char* s_headerCommitment;
    char* s_nBits;
    char* s_start_nonce;
    char* s_ntime;
    bool clean, ret = false;

    job_id = json_array_string(val, 0);
    s_candidateId = json_array_string(val, 1);
    s_headerCommitment = json_array_string(val, 2);
    s_nBits = json_array_string(val, 3);
    s_start_nonce = json_array_string(val, 4);
    s_ntime = json_array_string(val, 5);
    clean = json_is_true(json_array_get(val, 6));

    if (!job_id || !s_candidateId || !s_headerCommitment || !s_nBits || !s_start_nonce || !s_ntime)
    {
        /* Annoying but we must not leak memory */
        if (job_id)
        {
            free(job_id);
        }
        if (s_candidateId)
        {
            free(s_candidateId);
        }
        if (s_headerCommitment)
        {
            free(s_headerCommitment);
        }
        if (s_nBits)
        {
            free(s_nBits);
        }
        if (s_start_nonce)
        {
            free(s_start_nonce);
        }
        if (s_ntime)
        {
			free(s_ntime);
        }
        goto out;
    }

    cg_wlock(&pool->data_lock);
    free(pool->swork.job_id);
    free(pool->swork.ntime);
    pool->swork.job_id = job_id;
    pool->swork.ntime = s_ntime;
    char* end;
    pool->swork.candidateId = (uint64_t)strtoull(s_candidateId, &end, 10);
    size_t i = 0;
    // this unpacking is weird because python is confusing and it was easier
    // to figure out a solution in c than python
    for (size_t j = 0; j < 32; ++j)
    {
        sscanf(&s_headerCommitment[i], "%2hhx", &pool->swork.headerCommitment[j]);
        i += 2;
    }
    pool->swork.nBits = (uint32_t)strtoul(s_nBits, &end, 16);
    i = 0;
    for (size_t j = 0; j < 16; ++j)
    {
        sscanf(&s_start_nonce[i], "%2hhx", &pool->swork.start_nonce[j]);
        i += 2;
    }
    pool->swork.clean = clean;
    cg_wunlock(&pool->data_lock);

    if (opt_protocol)
    {
        applog(LOG_DEBUG, "job_id: %s\n", pool->swork.job_id);
        applog(LOG_DEBUG, "candidateId: %lu\n", pool->swork.candidateId);
        char* hash_str;
        hash_str = bin2hex(pool->swork.headerCommitment, 32);
        applog(LOG_DEBUG, "headerCommitment: %s\n", hash_str);
        free(hash_str);
        applog(LOG_DEBUG, "start_nonce: %s\n", pool->swork.start_nonce);
        applog(LOG_DEBUG, "ntime: %s", pool->swork.ntime);
        applog(LOG_DEBUG, "clean: %s\n", clean ? "yes" : "no");
    }

    /* A notify message is the closest echelon gets to a getwork */
    pool->getwork_requested++;
    total_getworks++;
    ret = true;
out:
    return ret;
}

static bool parse_diff(struct pool *pool, json_t *val)
{
	double diff = json_number_value(json_array_get(val, 0));
	if (diff == 0)
    {
		return false;
    }
	cg_wlock(&pool->data_lock);
	pool->swork.diff = diff;
	cg_wunlock(&pool->data_lock);
	applog(LOG_INFO, "Pool %d difficulty set to %f", pool->pool_no, diff);
	return true;
}

static bool parse_reconnect(struct pool* pool, json_t* val)
{
    char *url, *port, address[256];

    memset(address, 0, 255);
    url = (char*)json_string_value(json_array_get(val, 0));
    if (!url)
        url = pool->sockaddr_url;

    port = (char*)json_string_value(json_array_get(val, 1));
    if (!port)
        port = pool->echelon_port;

    sprintf(address, "%s:%s", url, port);

    if (!extract_sockaddr(pool, address))
        return false;

    pool->echelon_url = pool->sockaddr_url;

    applog(LOG_NOTICE, "Reconnect requested from pool %d to %s", pool->pool_no, address);

    if (!restart_echelon(pool))
        return false;

    return true;
}

static bool send_version(struct pool* pool, json_t* val)
{
    char s[RBUFSIZE];
    int id = json_integer_value(json_object_get(val, "id"));

    if (!id)
        return false;

    sprintf(s, "{\"id\": %d, \"result\": \"" PACKAGE_NAME "/" PACKAGE_VERSION "\", \"error\": null}", id);
    if (!echelon_send(pool, s, strlen(s)))
        return false;

    return true;
}

void dev_error(struct cgpu_info* dev, enum dev_reason reason)
{
    dev->device_last_not_well = time(NULL);
    dev->device_not_well_reason = reason;

    switch (reason)
    {
    case REASON_THREAD_FAIL_INIT:
        dev->thread_fail_init_count++;
        break;
    case REASON_THREAD_ZERO_HASH:
        dev->thread_zero_hash_count++;
        break;
    case REASON_THREAD_FAIL_QUEUE:
        dev->thread_fail_queue_count++;
        break;
    case REASON_DEV_SICK_IDLE_60:
        dev->dev_sick_idle_60_count++;
        break;
    case REASON_DEV_DEAD_IDLE_600:
        dev->dev_dead_idle_600_count++;
        break;
    case REASON_DEV_NOSTART:
        dev->dev_nostart_count++;
        break;
    case REASON_DEV_OVER_HEAT:
        dev->dev_over_heat_count++;
        break;
    case REASON_DEV_THERMAL_CUTOFF:
        dev->dev_thermal_cutoff_count++;
        break;
    case REASON_DEV_COMMS_ERROR:
        dev->dev_comms_error_count++;
        break;
    case REASON_DEV_THROTTLE:
        dev->dev_throttle_count++;
        break;
    }
}

void RenameThread(const char* name)
{
#if defined(PR_SET_NAME)
    // Only the first 15 characters are used (16 - NUL terminator)
    prctl(PR_SET_NAME, name, 0, 0, 0);
#elif (defined(__FreeBSD__) || defined(__OpenBSD__))
    pthread_set_name_np(pthread_self(), name);
#elif defined(MAC_OSX)
    pthread_setname_np(name);
#else
    // Prevent warnings for unused parameters...
    (void)name;
#endif
}
