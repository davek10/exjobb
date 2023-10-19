#include <string.h>
#include <zephyr/sys/printk.h>
#include "mitm.h"
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>


#define MY_ACTIVATE_MITM


LOG_MODULE_DECLARE(log1, LOG_LEVEL_DBG);

static bt_addr_le_t  my_target;
static bool my_target_set = false;
static bool my_mitm_started = false;

struct my_mitm_info target_mitm_info;
K_SEM_DEFINE(target_sem, 0, 1);

int my_init_mitm(){
  sys_slist_init(&target_mitm_info.ad_slist);
  sys_slist_init(&target_mitm_info.sd_slist);

  target_mitm_info.ad_map = 0UL;
  target_mitm_info.sd_map = 0UL;

  target_mitm_info.ad_amount = 0;
  target_mitm_info.sd_amount = 0;

  return 0;
}

bool my_check_bit(unsigned long map, uint8_t bit)
{
  uint8_t _bit = (bit == 0xff) ? 0x2f : bit;
  return MY_CHECK_BIT(map,_bit);
}

unsigned long my_set_bit(unsigned long map, uint8_t bit)
{
  uint8_t _bit = (bit == 0xff) ? 0x2f : bit;
  return MY_SET_BIT(map,_bit);
}

int my_activate_mitm()
{
  if(!my_target_set){
    LOG_ERR("cant start mitm, no active target \n");
    return -1;
  }

  if (target_mitm_info.ad_amount < 1 || target_mitm_info.sd_amount < 1)
  {
    return 0;
  }

  my_mitm_started = true;
  k_sem_give(&target_sem);
  return 0;
 }

 bool get_my_target_set()
 {
   return my_target_set;
 }

 void set_my_mitm_started(bool new_my_mitm_started)
 {
   my_mitm_started = new_my_mitm_started;
 }

 bool get_my_mitm_started()
 {
   return my_mitm_started;
 }

 int set_my_target(const char *target, const char *type)
 {
  bt_addr_le_from_str(target,type, &target_mitm_info.addr);
  strncpy(&target_mitm_info.addr_str, target, BT_ADDR_LE_STR_LEN);

  my_target_set = true;
  return 0;
 }

 const bt_addr_le_t* get_my_target()
 {
  return &target_mitm_info.addr;
 }

 void my_print_mitm_info(const struct my_mitm_info *mitm_info){
  LOG_INF("\n \r name: %s \n \r addr: %s \n \r man info: %x \n \r flags: %x \n", mitm_info->name, mitm_info->addr_str, mitm_info->man_data, mitm_info->flags);
 }

 int my_mitm_start_ad(){
  //bt_set_name(target_mitm_info.name);

  size_t total_ad_size = target_mitm_info.nr_ad_fields * sizeof(struct bt_data);
  struct bt_data *my_ad = k_malloc(total_ad_size);
  if (!my_ad)
  {
    LOG_ERR("Failed to allocate memory for advertisement data\n");
    return -1;
  }

  size_t total_sd_size = target_mitm_info.nr_sd_fields * sizeof(struct bt_data);
  struct bt_data *my_sd = k_malloc(total_sd_size);
  if (!my_sd)
  {
    LOG_ERR("Failed to allocate memory for scan response data\n");
    return -1;
  }

  int my_ad_size = my_fill_array(&target_mitm_info.ad_slist, my_ad);
  int my_sd_size = my_fill_array(&target_mitm_info.sd_slist, my_sd);

  int err = 0;

#ifdef MY_ACTIVATE_MITM
  int _identity_id = bt_id_create(&target_mitm_info.addr, NULL);
  if(_identity_id < 0 ){
    LOG_ERR("Unable to create new bluetooth identity (err %d)\n", _identity_id);
    return _identity_id;
  }

  struct bt_le_adv_param my_params = BT_LE_ADV_PARAM_INIT(   \
    (BT_LE_ADV_OPT_CONNECTABLE | BT_LE_ADV_OPT_USE_IDENTITY), \
    BT_GAP_ADV_FAST_INT_MIN_2, BT_GAP_ADV_FAST_INT_MAX_2, NULL);
  my_params.id = _identity_id;
  err = bt_le_adv_start(&my_params, my_ad, target_mitm_info.nr_ad_fields, my_sd, target_mitm_info.nr_sd_fields);
#endif

  if(err){
    LOG_ERR("could not start advertisement err: %d \n", err);
    return -1;
  }
  LOG_INF("STARTED ADVERTISMENT \n");
  k_free(my_ad);
  k_free(my_sd);

  return 0;
 }


 int my_mitm_add_ad(uint8_t type, void *data, uint8_t data_len, bool is_sd)
 {

  if ((is_sd && my_check_bit(target_mitm_info.sd_map, type)) || (!is_sd && my_check_bit(target_mitm_info.ad_map, type)))
  {
      return 0;
  }

  struct my_node *node = k_malloc(sizeof(struct my_node));

  struct bt_data tmp_data = BT_DATA(type, data, data_len);
  node->data = tmp_data;

  if(is_sd){
    sys_slist_append(&target_mitm_info.sd_slist, &(node->node));
    target_mitm_info.nr_sd_fields++;
    target_mitm_info.sd_map = my_set_bit(target_mitm_info.sd_map, type);
  }else{
    sys_slist_append(&target_mitm_info.ad_slist, &(node->node));
    target_mitm_info.nr_ad_fields++;
    target_mitm_info.ad_map = my_set_bit(target_mitm_info.ad_map, type);
  }
  return 0;
}


int my_fill_array(sys_slist_t *lst, struct bt_data *arr){
  int i = 0;
  struct my_node *c;
  struct my_node *cn;
  SYS_SLIST_FOR_EACH_CONTAINER_SAFE(lst, c, cn, node)
  {
    arr[i] = c->data;

    k_free(c);
    i++;
  }
  return i;
}