#ifndef MY_DB
#define MY_DB

#include <zephyr/sys/slist.h>
#include <zephyr/bluetooth/gatt.h>

struct my_db_entry
{
    uint16_t handle;
    void *data;
};

struct my_db_node
{
    struct my_db_entry data;
    sys_snode_t node;
};

int my_read_db_entry(uint16_t handle, void *buffer, int len);
int my_write_db_entry(uint16_t handle, void *buffer, int len);
int my_read_db_entry(uint16_t handle, void *buffer, int len);

#endif