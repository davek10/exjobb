#include <string.h>
#include <zephyr/sys/printk.h>
#include "mitm.h"
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include "myutil.h"

#define MY_ACTIVATE_MITM


LOG_MODULE_DECLARE(log1, APP_LOG_LEVEL);

static bt_addr_le_t  my_target;
static bool my_target_set = false;
static bool my_mitm_started = false;
struct bt_le_ext_adv *my_adv_set;

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
  static int cnt = 0;

  if(!my_target_set){
    LOG_ERR("cant start mitm, no active target \n");
    return -1;
  }

  if ((target_mitm_info.ad_amount < 1 || target_mitm_info.sd_amount < 1) && cnt < MY_MITM_AD_WAIT_LIMIT)
  {
    cnt++;
    return 0;
  }

  my_mitm_started = true;
  cnt = 0;
  k_sem_give(&target_sem);
  return 0;
 }

 bool get_my_target_set()
 {
   return my_target_set;
 }

 void set_my_target_set(bool value)
 {
   my_target_set = value;
   return;
 }

 void set_my_mitm_started(bool new_my_mitm_started)
 {
   my_mitm_started = new_my_mitm_started;
 }

 bool get_my_mitm_started()
 {
   return my_mitm_started;
 }

 void set_my_mitm_address_id(unsigned int id){
  target_mitm_info.address_id = id;
 }

 int set_my_target(const char *target, const char *type)
 {
   if (strncmp(target, "-1", sizeof("-1")) == 0){
     return set_my_target("F7:E1:36:7C:5B:AB", "random");
   }

   int err = bt_addr_le_from_str(target, type, &target_mitm_info.addr);
   if(err){
    LOG_ERR("Failed to set target: %s, %s err: %d", target, type,err);
    return err;
   }

   strncpy(&target_mitm_info.addr_str, target, BT_ADDR_LE_STR_LEN);
   LOG_INF("New target set: %s, %s", target, type);
   return 0;
 }

 const bt_addr_le_t* get_my_target()
 {
  return &target_mitm_info.addr;
 }

 bool my_mitm_get_is_coded(){
  return target_mitm_info.coded_phy;
 }

 void my_print_mitm_info(const struct my_mitm_info *mitm_info){
  LOG_INF("\n \r name: %s \n \r addr: %s \n \r man info: %x \n \r flags: %x \n", mitm_info->name, mitm_info->addr_str, mitm_info->man_data, mitm_info->flags);
 }

 int my_mitm_start_ad(){
  //bt_set_name(target_mitm_info.name);

  struct bt_data *my_ad = NULL;
  struct bt_data *my_sd = NULL;

      if (target_mitm_info.nr_ad_fields > 0)
  {
    size_t total_ad_size = target_mitm_info.nr_ad_fields * sizeof(struct bt_data);
    my_ad = k_malloc(total_ad_size);
    if (!my_ad)
    {
      LOG_ERR("Failed to allocate memory for advertisement data\n");
      return -1;
    }
    int my_ad_size = my_fill_array(&target_mitm_info.ad_slist, my_ad);
  }
  if(target_mitm_info.nr_sd_fields > 0){
    size_t total_sd_size = target_mitm_info.nr_sd_fields * sizeof(struct bt_data);
    my_sd = k_malloc(total_sd_size);
    if (!my_sd)
    {
      LOG_ERR("Failed to allocate memory for scan response data\n");
      return -1;
    }

    int my_sd_size = my_fill_array(&target_mitm_info.sd_slist, my_sd);
  }
  int err = 0;

#ifdef MY_ACTIVATE_MITM


    struct bt_le_adv_param my_params = BT_LE_ADV_PARAM_INIT(
        (BT_LE_ADV_OPT_CONNECTABLE | BT_LE_ADV_OPT_USE_IDENTITY | (target_mitm_info.ext_adv?BT_LE_ADV_OPT_EXT_ADV:0) | (target_mitm_info.coded_phy ? BT_LE_ADV_OPT_CODED:0)),
        BT_GAP_ADV_FAST_INT_MIN_2, BT_GAP_ADV_FAST_INT_MAX_2, NULL);
    
    int id = bt_id_create(get_my_target(),NULL);
    if(id<0){
      LOG_ERR("ERROR CREATING ID");
    }
    my_params.id = id;
    err = bt_set_name(target_mitm_info.name);
    err = bt_set_appearance(target_mitm_info.appearance);

    

  if(target_mitm_info.ext_adv || target_mitm_info.coded_phy){
    err = bt_le_ext_adv_create(&my_params, NULL,&my_adv_set);
    if(err){
      LOG_ERR("could not create extended adv set, err: %d", err);
      return err;
    }
    err = bt_le_ext_adv_set_data(my_adv_set, my_ad, target_mitm_info.nr_ad_fields, my_sd, target_mitm_info.nr_sd_fields);
    if (err)
    {
      LOG_ERR("could not set extended adv data, err: %d", err);
      return err;
    }
   err =  bt_le_ext_adv_start(my_adv_set,NULL);

  }else{
    
    err = bt_le_adv_start(&my_params, my_ad, target_mitm_info.nr_ad_fields, my_sd, target_mitm_info.nr_sd_fields);
  }

  // end if MY_ACTIVATE_MITM
#endif

  if(err){
    LOG_ERR("could not start advertisement err: %d \n", err);
    return -1;
  }
  LOG_INF("STARTED ADVERTISMENT \n");
  k_free(my_ad);
  k_free(my_sd);

  k_sem_give(&target_sem);

  return 0;
 }

 
 int my_mitm_add_ad(uint8_t type, void *data, uint8_t data_len, bool is_sd, bool is_bt_data)
 {

  if ((is_sd && my_check_bit(target_mitm_info.sd_map, type)) || (!is_sd && my_check_bit(target_mitm_info.ad_map, type)))
  {
      return 0;
  }

  struct my_node *node = k_malloc(sizeof(struct my_node));

  if(is_bt_data){
    struct bt_data *tmp_data = data;
    struct bt_data tmp_data_cpy;
    tmp_data_cpy.data_len = tmp_data->data_len;
    tmp_data_cpy.type = tmp_data->type;
    uint8_t *data_cpy = k_malloc(tmp_data->data_len);
    memcpy(data_cpy, tmp_data->data, tmp_data->data_len);
    tmp_data_cpy.data = data_cpy;
    node->data = tmp_data_cpy;
  }else{
    struct bt_data tmp_data = BT_DATA(type, data, data_len);
    node->data = tmp_data;
  }

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