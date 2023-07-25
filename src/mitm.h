#ifndef MY_MITM
#define MY_MITM

#define NAME_LEN 30
#include <stdbool.h>
#include <zephyr/bluetooth/addr.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/slist.h>
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/bluetooth/bluetooth.h>

#define MY_CHECK_BIT(__u,__n) ((__u) & (1UL <<(__n)))
#define MY_SET_BIT(__u,__n) ((__u) | (1UL <<__n))

extern struct k_sem target_sem;

struct my_mitm_info {
    char name[NAME_LEN];
    uint8_t name_len;
    bool ext_adv;
    bool fullname;
    bt_addr_le_t addr;
    uint8_t ad_type;
    uint8_t flags;
    uint8_t man_data;
    //uint8_t phy1,phy2;
    char phy1[20], phy2[20];
    char addr_str[BT_ADDR_LE_STR_LEN];
    struct bt_uuid_128 uuid128;
    struct bt_uuid_32 uuid32;
    struct bt_uuid_16 uuid16;
    sys_slist_t ad_slist;
    sys_slist_t sd_slist;
    int nr_ad_fields;
    int nr_sd_fields;
    unsigned long ad_map;
    unsigned long sd_map;
    unsigned int ad_amount;
    unsigned int sd_amount;
};

    struct my_callback_struct
{
    struct my_mitm_info *mitm_info;
    bool is_sr;
};

struct my_node{
    sys_snode_t node;
    struct bt_data data;
};


extern struct my_mitm_info target_mitm_info;

bool get_my_target_set();
bool get_my_mitm_started();
int my_activate_mitm();
const bt_addr_le_t* get_my_target();
int set_my_target(const char *target, const char* type);
void my_print_mitm_info(const struct my_mitm_info *mitm_info);
int my_mitm_add_ad(uint8_t type,void *data, uint8_t data_len, bool is_sd);
int my_mitm_start_ad();
void my_set_mitm_bit(bool is_sr, uint8_t type);
int my_init_mitm();
int my_fill_array(sys_slist_t *my_slist, struct bt_data *data);
unsigned long my_set_bit(unsigned long map, uint8_t bit);
bool my_check_bit(unsigned long map, uint8_t bit);

#endif