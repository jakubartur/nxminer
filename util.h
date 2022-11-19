#ifndef __UTIL_H__
#define __UTIL_H__

#if defined(unix) || defined(__APPLE__)
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define SOCKETTYPE    long
#define SOCKETFAIL(a) ((a) < 0)
#define INVSOCK       -1
#define INVINETADDR   -1
#define CLOSESOCKET   close

#define SOCKERRMSG strerror(errno)
#elif defined WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

#define SOCKETTYPE    SOCKET
#define SOCKETFAIL(a) ((int)(a) == SOCKET_ERROR)
#define INVSOCK       INVALID_SOCKET
#define INVINETADDR   INADDR_NONE
#define CLOSESOCKET   closesocket

extern char* WSAErrorMsg(void);
#define SOCKERRMSG    WSAErrorMsg()

#ifndef SHUT_RDWR
#define SHUT_RDWR SD_BOTH
#endif

#ifndef in_addr_t
#define in_addr_t uint32_t
#endif
#endif

#if JANSSON_MAJOR_VERSION >= 2
#define JSON_LOADS(str, err_ptr) json_loads((str), 0, (err_ptr))
#else
#define JSON_LOADS(str, err_ptr) json_loads((str), (err_ptr))
#endif

struct pool;
enum dev_reason;
struct cgpu_info;

void difficulty_to_target(double difficulty, uint8_t* res);
void nonce_assign_addition(uint8_t* a, const uint64_t b);
double nbits_to_difficulty(const uint32_t* nBits);
bool stratum_send(struct pool* pool, char* s, ssize_t len);
bool sock_full(struct pool* pool);
char* recv_line(struct pool* pool);
bool parse_method(struct pool* pool, char* s);
bool extract_sockaddr(struct pool* pool, char* url);
bool auth_stratum(struct pool* pool);
bool initiate_stratum(struct pool* pool);
bool restart_stratum(struct pool* pool);
void suspend_stratum(struct pool* pool);
void dev_error(struct cgpu_info* dev, enum dev_reason reason);
void RenameThread(const char* name);

/* Align a size_t to 4 byte boundaries for fussy arches */
static inline void align_len(size_t* len)
{
    if (*len % 4)
        *len += 4 - (*len % 4);
}

#endif /* __UTIL_H__ */
