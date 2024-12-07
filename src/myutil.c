#include <string.h>
#include <stdlib.h>
#include "myutil.h"
#include "zephyr/logging/log.h"



LOG_MODULE_DECLARE(log1, APP_LOG_LEVEL);

uint32_t my_str_to_uint(char *buf, size_t max_len)
{
    size_t len = strnlen(buf, max_len);
    uint32_t res = 0;
    bool first = true;
    for (uint32_t i = 0; i < len; i++)
    {
        char c = buf[i];

        if (c < 48 || c > 57)
        {
            return -1;
        }
        LOG_DBG("c: %u, len: %u, i: %u, len-i: %u", (c - '0'), len, i, len - i);
        res += (c - '0') * my_naive_pow(10, len - i - 1);
    }
    return res;
}