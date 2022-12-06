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

#include <jansson.h>

#include "echelon.h"

bool restart_echelon(struct pool* pool)
{
    if (pool->echelon_active)
    {
        suspend_echelon(pool);
    }
    if (!initiate_echelon(pool))
    {
        return false;
    }
    if (!auth_echelon(pool))
    {
        return false;
    }
    return true;
}

/* Send a single command across a socket, appending \n to it. This should all
 * be done under stratum lock except when first establishing the socket */
static bool __echelon_send(struct pool* pool, char* s, ssize_t len)
{
    SOCKETTYPE sock = pool->sock;
    ssize_t ssent = 0;
    if (opt_protocol)
    {
        applog(LOG_DEBUG, "SEND: %s", s);
    }
    strcat(s, "\n");
    len++;
    while (len > 0)
    {
        struct timeval timeout = {1, 0};
        ssize_t sent;
        fd_set wd;
        FD_ZERO(&wd);
        FD_SET(sock, &wd);
        if (select(sock + 1, NULL, &wd, NULL, &timeout) < 1)
        {
            applog(LOG_DEBUG, "Write select failed on pool %d sock", pool->pool_no);
            return false;
        }
#ifdef __APPLE__
		sent = send(pool->sock, s + ssent, len, SO_NOSIGPIPE);
#elif WIN32
		sent = send(pool->sock, s + ssent, len, 0);
#else
		sent = send(pool->sock, s + ssent, len, MSG_NOSIGNAL);
#endif
        if (sent < 0)
        {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
            {
                applog(LOG_DEBUG, "Failed to curl_easy_send in stratum_send");
                return false;
            }
            sent = 0;
        }
        ssent += sent;
        len -= sent;
    }
    pool->cgminer_pool_stats.times_sent++;
    pool->cgminer_pool_stats.bytes_sent += ssent;
    pool->cgminer_pool_stats.net_bytes_sent += ssent;
    return true;
}

static char* get_sessionid(json_t* val)
{
    char* ret = NULL;
    json_t* arr_val;
    int arrsize, i;

    arr_val = json_array_get(val, 0);
    if (!arr_val || !json_is_array(arr_val))
    {
        return ret;
    }
    arrsize = json_array_size(arr_val);
    for (i = 0; i < arrsize; i++)
    {
        json_t* arr = json_array_get(arr_val, i);
        char* notify;
        if (!arr | !json_is_array(arr))
        {
            break;
        }
        notify = __json_array_string(arr, 0);
        if (!notify)
        {
            continue;
        }
        if (!strncasecmp(notify, "mining.notify", 13))
        {
            ret = json_array_string(arr, 1);
            break;
        }
    }
    return ret;
}

static bool setup_echelon_curl(struct pool* pool)
{
    char curl_err_str[CURL_ERROR_SIZE];
    CURL* curl = NULL;
    double byte_count;
    char s[RBUFSIZE];

    mutex_lock(&pool->echelon_lock);
    pool->echelon_active = false;
    if (pool->echelon_curl)
    {
        curl_easy_cleanup(pool->echelon_curl);
    }
    pool->echelon_curl = curl_easy_init();
    if (unlikely(!pool->echelon_curl))
    {
        nxquit(1, "Failed to curl_easy_init in initiate_stratum");
    }
    mutex_unlock(&pool->echelon_lock);
    curl = pool->echelon_curl;

    if (!pool->sockbuf)
    {
        pool->sockbuf = calloc(RBUFSIZE, 1);
        if (!pool->sockbuf)
        {
            nxquit(1, "Failed to calloc pool sockbuf in initiate_stratum");
        }
        pool->sockbuf_size = RBUFSIZE;
    }

    /* Create a http url for use with curl */
    sprintf(s, "http://%s:%s", pool->sockaddr_url, pool->echelon_port);

    curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err_str);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl, CURLOPT_URL, s);
    curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_TRY);
    if (pool->rpc_proxy)
    {
        curl_easy_setopt(curl, CURLOPT_PROXY, pool->rpc_proxy);
        curl_easy_setopt(curl, CURLOPT_PROXYTYPE, pool->rpc_proxytype);
    }
    else if (opt_socks_proxy)
    {
        curl_easy_setopt(curl, CURLOPT_PROXY, opt_socks_proxy);
        curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS4);
    }
    curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1);
    if (curl_easy_perform(curl))
    {
        applog(LOG_INFO, "Stratum connect failed to pool %d: %s", pool->pool_no, curl_err_str);
        return false;
    }
    curl_easy_getinfo(curl, CURLINFO_LASTSOCKET, (long*)&pool->sock);
    keep_alive(curl, pool->sock);

    pool->cgminer_pool_stats.times_sent++;
    if (curl_easy_getinfo(curl, CURLINFO_SIZE_UPLOAD, &byte_count) == CURLE_OK)
    {
        pool->cgminer_pool_stats.bytes_sent += byte_count;
    }
    pool->cgminer_pool_stats.times_received++;
    if (curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD, &byte_count) == CURLE_OK)
    {
        pool->cgminer_pool_stats.bytes_received += byte_count;
    }

    return true;
}

bool initiate_echelon(struct pool* pool)
{
    bool ret = false, recvd = false, noresume = false, sockd = false;
    char s[RBUFSIZE], *sret = NULL, *nonce1, *sessionid;
    json_t *val = NULL, *res_val, *err_val;
    json_error_t err;
    int n2size;

resend:
    if (!setup_echelon_curl(pool))
    {
        sockd = false;
        goto out;
    }

    sockd = true;

    if (recvd)
    {
        /* Get rid of any crap lying around if we're resending */
        clear_sock(pool);
        sprintf(s, "{\"id\": %d, \"method\": \"mining.subscribe\", \"params\": []}", swork_id++);
    }
    else
    {
        if (pool->sessionid)
        {
            sprintf(s,
                "{\"id\": %d, \"method\": \"mining.subscribe\", \"params\": [\"" PACKAGE_NAME "/" PACKAGE_VERSION "\", \"%s\"]}",
                swork_id++, pool->sessionid);
        }
        else
        {
            sprintf(s, "{\"id\": %d, \"method\": \"mining.subscribe\", \"params\": [\"" PACKAGE_NAME "/" PACKAGE_VERSION "\"]}",
                swork_id++);
        }
    }

    if (!__echelon_send(pool, s, strlen(s)))
    {
        applog(LOG_DEBUG, "Failed to send s in initiate_stratum");
        goto out;
    }

    if (!socket_full(pool, true))
    {
        applog(LOG_DEBUG, "Timed out waiting for response in initiate_stratum");
        goto out;
    }

    sret = recv_line(pool);
    if (!sret)
    {
        goto out;
    }

    recvd = true;

    val = JSON_LOADS(sret, &err);
    free(sret);
    if (!val)
    {
        applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
        goto out;
    }

    res_val = json_object_get(val, "result");
    err_val = json_object_get(val, "error");

    if (!res_val || json_is_null(res_val) || (err_val && !json_is_null(err_val)))
    {
        char* ss;
        if (err_val)
        {
            ss = json_dumps(err_val, JSON_INDENT(3));
        }
        else
        {
            ss = strdup("(unknown reason)");
        }
        applog(LOG_INFO, "JSON-RPC decode failed: %s", ss);
        free(ss);
        goto out;
    }

    sessionid = get_sessionid(res_val);
    if (!sessionid)
    {
        applog(LOG_DEBUG, "Failed to get sessionid in initiate_stratum");
    }
    nonce1 = json_array_string(res_val, 1);
    if (!nonce1)
    {
        applog(LOG_INFO, "Failed to get nonce1 in initiate_stratum");
        free(sessionid);
        goto out;
    }

    cg_wlock(&pool->data_lock);
    pool->sessionid = sessionid;
    char* end;
    pool->nonce1 = (uint16_t)strtoul(nonce1, &end, 10);
    cg_wunlock(&pool->data_lock);

    if (sessionid)
    {
        applog(LOG_DEBUG, "Pool %d stratum session id: %s", pool->pool_no, pool->sessionid);
    }
    ret = true;
out:
    if (ret)
    {
        if (!pool->echelon_url)
        {
            pool->echelon_url = pool->sockaddr_url;
        }
        pool->echelon_active = true;
        if (opt_protocol)
        {
            applog(LOG_DEBUG, "Pool %d confirmed mining.subscribe with extranonce1 %u", pool->pool_no, pool->nonce1);
        }
    }
    else
    {
        if (recvd && !noresume)
        {
            /* Reset the sessionid used for stratum resuming in case the pool
             * does not support it, or does not know how to respond to the
             * presence of the sessionid parameter. */
            cg_wlock(&pool->data_lock);
            free(pool->sessionid);
            pool->sessionid = 0;
            pool->nonce1 = 0;
            cg_wunlock(&pool->data_lock);
            applog(LOG_DEBUG, "Failed to resume stratum, trying afresh");
            noresume = true;
            goto resend;
        }
        applog(LOG_DEBUG, "Initiate stratum failed");
        if (sockd)
        {
            suspend_echelon(pool);
        }
    }

    return ret;
}

static bool show_message(struct pool* pool, json_t* val)
{
    char* msg;
    if (!json_is_array(val))
    {
        return false;
    }
    msg = (char*)json_string_value(json_array_get(val, 0));
    if (!msg)
    {
        return false;
    }
    applog(LOG_NOTICE, "Pool %d message: %s", pool->pool_no, msg);
    return true;
}

bool parse_echelon_method(struct pool* pool, char* s)
{
    json_t *val = NULL, *method, *err_val, *params;
    json_error_t err;
    bool ret = false;
    char* buf;

    if (!s)
    {
        return ret;
    }
    val = JSON_LOADS(s, &err);
    if (!val)
    {
        applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
        return ret;
    }
    method = json_object_get(val, "method");
    if (!method)
    {
        return ret;
    }
    err_val = json_object_get(val, "error");
    params = json_object_get(val, "params");

    if (err_val && !json_is_null(err_val))
    {
        char* ss;
        if (err_val)
        {
            ss = json_dumps(err_val, JSON_INDENT(3));
        }
        else
        {
            ss = strdup("(unknown reason)");
        }
        applog(LOG_INFO, "JSON-RPC method decode failed: %s", ss);
        free(ss);
        return ret;
    }

    buf = (char*)json_string_value(method);
    if (!buf)
    {
        return ret;
    }

    if (!strncasecmp(buf, "mining.notify", 13))
    {
        if (parse_notify(pool, params))
        {
            pool->echelon_notify = ret = true;
        }
        else
        {
            pool->echelon_notify = ret = false;
        }
        return ret;
    }

    if (!strncasecmp(buf, "mining.set_difficulty", 21) && parse_diff(pool, params))
    {
        ret = true;
        return ret;
    }

    if (!strncasecmp(buf, "client.reconnect", 16) && parse_reconnect(pool, params))
    {
        ret = true;
        return ret;
    }

    if (!strncasecmp(buf, "client.get_version", 18) && send_version(pool, val))
    {
        ret = true;
        return ret;
    }

    if (!strncasecmp(buf, "client.show_message", 19) && show_message(pool, params))
    {
        ret = true;
        return ret;
    }
    return ret;
}

bool auth_echelon(struct pool* pool)
{
    json_t *val = NULL, *res_val, *err_val;
    char s[RBUFSIZE], *sret = NULL;
    json_error_t err;
    bool ret = false;

    sprintf(s, "{\"id\": %d, \"method\": \"mining.authorize\", \"params\": [\"%s\", \"%s\"]}", swork_id++,
        pool->rpc_user, pool->rpc_pass);

    if (!echelon_send(pool, s, strlen(s)))
    {
        return ret;
    }

    /* Parse all data in the queue and anything left should be auth */
    while (42)
    {
        sret = recv_line(pool);
        if (!sret)
        {
            return ret;
        }
        if (parse_echelon_method(pool, sret))
        {
            free(sret);
        }
        else
        {
            break;
        }
    }

    val = JSON_LOADS(sret, &err);
    free(sret);
    res_val = json_object_get(val, "result");
    err_val = json_object_get(val, "error");

    if (!res_val || json_is_false(res_val) || (err_val && !json_is_null(err_val)))
    {
        char* ss;

        if (err_val)
        {
            ss = json_dumps(err_val, JSON_INDENT(3));
        }
        else
        {
            ss = strdup("(unknown reason)");
        }
        applog(LOG_WARNING, "pool %d JSON stratum auth failed: %s", pool->pool_no, ss);
        free(ss);
        return ret;
    }
    ret = true;
    applog(LOG_INFO, "Stratum authorisation success for pool %d", pool->pool_no);
    pool->probed = true;
    successful_connect = true;
    return ret;
}

bool echelon_send(struct pool* pool, char* s, ssize_t len)
{
    bool ret = false;
    mutex_lock(&pool->echelon_lock);
    if (pool->echelon_active)
    {
        ret = __echelon_send(pool, s, len);
    }
    else
    {
        applog(LOG_DEBUG, "Stratum send failed due to no pool echelon_active");
    }
    mutex_unlock(&pool->echelon_lock);
    return ret;
}

void suspend_echelon(struct pool* pool)
{
    clear_sockbuf(pool);
    applog(LOG_INFO, "Closing socket for stratum pool %d", pool->pool_no);
    mutex_lock(&pool->echelon_lock);
    pool->echelon_active = pool->echelon_notify = false;
    if (pool->echelon_curl)
    {
        curl_easy_cleanup(pool->echelon_curl);
    }
    pool->echelon_curl = NULL;
    mutex_unlock(&pool->echelon_lock);
}
