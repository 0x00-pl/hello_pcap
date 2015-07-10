#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <string.h>

char last_error[256];
static inline const char *get_last_error(){
    return last_error;
}

#if 0
#define IF_DEBUG(x) x
#else
#define IF_DEBUG(x)
#endif



#endif
