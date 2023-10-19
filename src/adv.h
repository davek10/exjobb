#ifndef MY_ADVERTISMENT
#define MY_ADVERTISMENT
#include <zephyr/sys/slist.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/conn.h>

extern struct k_sem adv_sem;


#define MY_ATTR_LIMIT 2

struct my_attr_node{
    sys_snode_t node;
    struct bt_gatt_attr attr;
    uint8_t type;
    uint8_t len;
};

struct my_char_perm{
    uint16_t perm;
    uint16_t prop;
};


int my_start_discovery();
void my_set_main_conn(struct bt_conn *new_conn);
struct bt_conn *my_get_main_conn();

#endif