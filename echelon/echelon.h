#ifndef __ECHELON_H__
#define __ECHELON_H__

#include "util.h"


bool restart_echelon(struct pool* pool);
bool initiate_echelon(struct pool* pool);
bool parse_echelon_method(struct pool* pool, char* s);
bool auth_echelon(struct pool* pool);
bool echelon_send(struct pool* pool, char* s, ssize_t len);
void suspend_echelon(struct pool* pool);

#endif /* __ECHELON_H__ */
