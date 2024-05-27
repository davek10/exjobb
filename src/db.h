#ifndef MY_DB
#define MY_DB

#include <zephyr/sys/slist.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/kernel.h>

#define MAX_RULES 5

typedef enum
{
    RULE_PASS = 0,
    RULE_BLOCK = 1,
    RULE_REPLACE = 2,
} my_rule_res_type;

struct my_rule
{
    uint32_t new_val;
    uint16_t handle;
    uint8_t dir;
    uint8_t set_new_val;
};

struct my_rule_res
{
    my_rule_res_type type;
    uint32_t data;
};

struct my_db_entry
{
    uint16_t handle;
    int len;
    void *data;
    struct bt_gatt_attr *attr;
};

struct my_db_node
{
    struct my_db_entry data;
    sys_snode_t node;
    struct k_sem sema;
    
};

struct my_ccc_entry{
    uint16_t ccc_handle;
    uint16_t char_handle;
    uint16_t value_handle;
};

struct my_ccc_node{
    sys_snode_t node;
    struct my_ccc_entry data;
    struct bt_gatt_subscribe_params params;
};



int my_db_add_entry(uint16_t handle, const void *buffer, uint16_t len, struct bt_gatt_attr *attr);
const struct bt_gatt_attr *my_db_write_entry(uint16_t handle, const void *buffer, uint16_t len, bool wake);
int my_db_read_entry(uint16_t handle, void *buffer, uint16_t len, bool wait);
int my_db_remove_entry(uint16_t handle);
int my_db_wait_for_entry(uint16_t handle);
const struct bt_gatt_attr* my_db_get_attr(uint16_t handle);

uint16_t my_get_char_handle(uint16_t ccc_handle);
uint16_t my_get_value_handle(uint16_t ccc_handle);
int my_add_ccc_entry(uint16_t ccc_handle, uint16_t char_handle);
int my_remove_ccc_entry(uint16_t ccc_handle);
int my_subscribe_to_all(struct bt_conn *conn, bt_gatt_subscribe_func_t func);
void my_db_foreach(void (*func)(uint16_t handle, struct bt_gatt_attr *attr, void *user_data), void *data);
int my_add_rule(bool dir, uint16_t handle, bool set_new_val, uint32_t new_val);
struct my_rule_res my_check_rules(uint8_t dir, uint16_t handle);

#endif