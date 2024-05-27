#ifndef MYUTIL
#define MYUTIL

#define APP_LOG_LEVEL 4

#define MY_CHECK_BIT(__u, __n) ((__u) & (1UL << (__n)))
#define MY_SET_BIT(__u, __n) ((__u) | (1UL << __n))

#endif