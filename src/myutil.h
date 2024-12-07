#ifndef MYUTIL
#define MYUTIL
#define APP_LOG_LEVEL 4

#include <zephyr/types.h>

#define MY_CHECK_BIT(__u, __n) ((__u) & (1UL << (__n)))
#define MY_SET_BIT(__u, __n) ((__u) | (1UL << __n))

uint32_t my_str_to_uint(char *buf, size_t max_len);

#endif