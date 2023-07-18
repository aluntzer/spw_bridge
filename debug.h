#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#define VERBOSE 0
#if VERBOSE
#define DBG printf
#else
#define DBG {}if(0)printf
#endif /* VERBOSE */



#endif /* DEBUG_H */
