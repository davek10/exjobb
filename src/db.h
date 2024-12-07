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

typedef enum
{
    ENTRY_PRIMARY,
    ENTRY_CHARACTERISTIC,
    ENTRY_CCC,
    ENTRY_DATA,
} my_entry_type;

struct my_rule
{
    uint8_t *new_val;
    uint16_t len;
    uint16_t handle;
    uint8_t dir;
    uint8_t set_new_val;
};

struct my_rule_res
{
    my_rule_res_type type;
    uint8_t *data;
    uint16_t len;
};

struct my_db_entry
{
    uint16_t handle;
    uint16_t type;
    int len;
    int max_len;
    void *data;
    struct bt_gatt_attr *attr;
};

struct my_db_node
{
    struct my_db_entry data;
    sys_snode_t node;
    struct k_sem sema;
    
};

struct my_db_entry *my_db_add_entry(uint16_t handle, my_entry_type type, struct bt_gatt_attr *attr);
void my_db_write_entry(uint16_t handle, const void *buffer, uint16_t len, bool wake);
int my_db_read_entry(uint16_t handle, void *buffer, uint16_t len, bool wait);
int my_db_remove_entry(uint16_t handle);
int my_db_wait_for_entry(uint16_t handle);
struct my_db_entry* my_db_get_entry(uint16_t handle);
int my_db_set_data_ptr(struct my_db_entry *entry1, struct my_db_entry *entry2);
int my_subscribe_to_all(struct bt_conn *conn, bt_gatt_subscribe_func_t func);
void my_db_foreach(void (*func)(uint16_t handle, struct bt_gatt_attr *attr, void *user_data), void *data);
int my_add_rule(bool dir, uint16_t handle, bool set_new_val, uint8_t *new_val, size_t len);
struct my_rule_res my_check_rules(uint8_t dir, uint16_t handle, const void *data, uint16_t len);
struct my_db_entry *my_db_ccc_to_value_handle(uint16_t ccc_handle);
uint16_t my_db_translate_handle(uint16_t handle, uint8_t dir);
size_t my_db_get_entry_data(struct my_db_entry *entry,void *buf, uint16_t len);
void my_db_translate_chrc_user_data();

#endif