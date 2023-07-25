#ifndef MY_ADVERTISMENT
#define MY_ADVERTISMENT
#include <zephyr/sys/slist.h>
#include <zephyr/bluetooth/gatt.h>

extern struct k_sem adv_sem;

struct my_attr_node{
    struct bt_gatt_attr attr;
    sys_snode_t node;
};

#endif