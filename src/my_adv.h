#ifndef MY_ADVERTISMENT
#define MY_ADVERTISMENT
#include <zephyr/sys/slist.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/conn.h>

#define MY_DEFAULT_LEN 1

extern struct k_sem adv_sem;


#define MY_ATTR_LIMIT 2

typedef enum
{
    UNDEFINED = 0,
    PRIMARY = 1,
    CHARACTERISTIC = 2,
    CCC = 3,
    VALUE = 4,
} my_attr_type;

struct my_attr_node{
    sys_snode_t node;
    struct bt_gatt_attr attr;
    my_attr_type type;
    uint8_t len;
};

struct my_char_perm{
    uint16_t perm;
    uint16_t prop;
};


int my_start_discovery();
void my_set_main_conn(struct bt_conn *new_conn);
struct bt_conn *my_get_main_conn();
int my_adv_subscribe_to_all();
void print_ccc_cfg_data(struct _bt_gatt_ccc *data);
int my_adv_wait_for_appearance();
struct bt_conn *my_adv_get_conn(uint32_t id);
int my_adv_reconnect(uint32_t id);

#endif