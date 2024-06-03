#include "db.h"
#include <zephyr/logging/log.h>
#include <zephyr/bluetooth/gatt.h>
#include "myutil.h"

LOG_MODULE_DECLARE(log1, APP_LOG_LEVEL);

#define MY_DB_DEFAULT_LEN 4

static sys_slist_t my_db = {NULL, NULL};
static sys_slist_t my_ccc_list = {NULL, NULL};

struct my_rule my_rules[MAX_RULES];
int num_rules = 0;


void print_rule(struct my_rule *rule){

        LOG_INF("rule: \n \t handle: %u, dir: %u, type:%s, new_value: %x",rule->handle,rule->dir,(rule->set_new_val ? "REPLACE":"BLOCK"),\
        (rule->set_new_val ? rule->new_val[0]:0));
}

int my_add_rule(bool dir, uint16_t handle, bool set_new_val, uint8_t *new_val, size_t len)
{

    if (num_rules == MAX_RULES)
    {
        return -1;
    }
    struct my_rule *tmp = &my_rules[num_rules];

    tmp->dir = dir;
    tmp->handle = handle;
    tmp->set_new_val = set_new_val;
    tmp->new_val = new_val;
    tmp->len = len;

    num_rules++;
    LOG_INF("new rule added: ");
    print_rule(tmp);
    return 0;
}

struct my_rule_res my_check_rules(uint8_t dir, uint16_t handle)
{
    struct my_rule_res res = {0,RULE_PASS,0};
    if (!num_rules)
    {
        return res;
    }
    for (int i = 0; i < num_rules; i++)
    {
        struct my_rule *tmp = &my_rules[i];
        print_rule(tmp);
        if (tmp->dir == dir && tmp->handle == handle)
        {
            if(tmp->set_new_val){
                res.type = RULE_REPLACE;
                res.data = tmp->new_val;
                res.len = tmp->len;
            }else{
                res.type = RULE_BLOCK;
            }
            
            return res;
        }
    }
    return res;
}

void my_db_foreach(void (*func)(uint16_t handle, struct bt_gatt_attr *attr, void* user_data),void *data){
    struct my_db_node *cn;
    SYS_SLIST_FOR_EACH_CONTAINER(&my_db, cn, node)
    {
       func(cn->data.handle,cn->data.attr,data);
    }
    return;
}


int my_db_add_entry(uint16_t handle, const void *data, uint16_t len, struct bt_gatt_attr *attr)
{
    LOG_DBG("adding entry with handle: %u", handle);
    struct my_db_node *node = k_malloc(sizeof(struct my_db_node));
    memset(node,0,sizeof(struct my_db_node));
    struct my_db_entry *entry = &node->data;
 
    entry->len = (len ? len : MY_DB_DEFAULT_LEN);
    entry->data = k_malloc(entry->len);
    entry->max_len = entry->len;
    entry->handle = handle;
    entry->attr = attr;
    k_sem_init(&node->sema,0,1);
    
    

    if(data == NULL){
        memset(entry->data, 0, entry->len);
    }else{
        memcpy(entry->data, data, entry->len);
    }
    sys_slist_append(&my_db, &node->node);
    return 0;
}

int my_db_read_entry(uint16_t handle, void *buffer, uint16_t len, bool wait)
{
    LOG_DBG("in read db");
    struct my_db_node *cn;
    SYS_SLIST_FOR_EACH_CONTAINER(&my_db, cn, node){
        LOG_DBG("current handle: %u, looking for handle: %u",cn->data.handle, handle);
        if(cn->data.handle == handle){
            
            #ifdef MY_CALLBACK_ATTEMPT
            int err = 0;
            if (wait)
            {
                LOG_DBG("starting to wait for handle %u ", handle);
                err = k_sem_take(&cn->sema, K_FOREVER);
            }
            #endif

            int length = MIN(cn->data.len, len); 
            memcpy(buffer, cn->data.data, length);
            return length;
        }
    }
    return -1;
}

const struct bt_gatt_attr *my_db_write_entry(uint16_t handle, const void *buffer, uint16_t len, bool wake)
{
    if (!buffer)
    {
        return NULL;
    }

    struct my_db_node *cn;
    SYS_SLIST_FOR_EACH_CONTAINER(&my_db, cn, node)
    {

        if (cn->data.handle == handle)
        {
            LOG_DBG("writing to db, handle: %u, first byte value: %x",cn->data.handle,((uint8_t *)buffer)[0]);
            if (len > cn->data.max_len){
                k_free(cn->data.data);
                cn->data.data = k_malloc(len);
                cn->data.max_len = len;
            }
            cn->data.len = len;
            memcpy(cn->data.data, buffer, len);
            
            #ifdef MY_CALLBACK_ATTEMPT
            if(wake){
                LOG_DBG("waking handle %u", handle);
                k_sem_give(&cn->sema);
            }
            #endif
            return cn->data.attr;
        }
    }

    return NULL;
}

int my_db_remove_entry(uint16_t handle)
{

    return 0;
}

int my_db_wait_for_entry(uint16_t handle)
{
    struct my_db_node *cn;
    SYS_SLIST_FOR_EACH_CONTAINER(&my_db, cn, node)
    {

        if (cn->data.handle == handle)
        {
            int err = k_sem_take(&cn->sema,K_FOREVER);
            return err;
        }
    }

    return -1;
}

const struct bt_gatt_attr * my_db_get_attr(uint16_t handle){

    struct my_db_node *cn;
    SYS_SLIST_FOR_EACH_CONTAINER(&my_db, cn, node)
    {

        if (cn->data.handle == handle)
        {
            return cn->data.attr;
        }
    }
    return NULL;
}

int my_add_ccc_entry(uint16_t ccc_handle, uint16_t char_handle, uint16_t value_handle){
    struct my_ccc_node *node = k_malloc(sizeof(struct my_ccc_node));
    memset(node, 0, sizeof(struct my_ccc_node));
    node->data.ccc_handle = ccc_handle;
    node->data.char_handle = char_handle;
    node->data.value_handle = value_handle;

    sys_slist_append(&my_ccc_list, node);
    return 0;
}

uint16_t my_get_char_handle(uint16_t ccc_handle){

    struct my_ccc_node *cn;
    SYS_SLIST_FOR_EACH_CONTAINER(&my_ccc_list, cn, node)
    {

        if (cn->data.ccc_handle == ccc_handle || cn->data.value_handle == ccc_handle)
        {
            return cn->data.char_handle;
        }
    }
    return 0;
}

uint16_t my_get_value_handle(uint16_t ccc_handle)
{

    struct my_ccc_node *cn;
    SYS_SLIST_FOR_EACH_CONTAINER(&my_ccc_list, cn, node)
    {

        if (cn->data.ccc_handle == ccc_handle || cn->data.char_handle == ccc_handle)
        {
            return cn->data.value_handle;
        }
    }
    return 0;
}

int my_remove_ccc_entry(uint16_t ccc_handle){

    return 0;
}

static void my_clean_sub_param(struct bt_gatt_subscribe_params *params){

    //k_free(params);
    return;
}

    void my_sub_callback(struct bt_conn *conn, uint8_t err,
                         struct bt_gatt_subscribe_params *params)
{
    LOG_DBG("sub_callback response with err: %u, char_handle = %u, ccc_handle = %u, notification value = %u",err,params->value_handle, params->ccc_handle, params->value);
    //my_clean_sub_param(params);
    LOG_INF("MITM module ready");
    return;
}

int my_subscribe_to_all(struct bt_conn *conn, bt_gatt_subscribe_func_t func){

    if(!conn){
        LOG_ERR("NO CONNN!");
        return -1;
    }

    struct my_ccc_node *cn;
    SYS_SLIST_FOR_EACH_CONTAINER(&my_ccc_list, cn, node)
    {
        LOG_DBG("found ccc thing with ccc_handle: %u, char_handle: %u value_handle %u",cn->data.ccc_handle, cn->data.char_handle, cn->data.value_handle);
        struct bt_gatt_subscribe_params *sub_param = &cn->params;
        sub_param->ccc_handle = cn->data.ccc_handle;
        sub_param->value_handle = cn->data.value_handle;
        sub_param->value = BT_GATT_CCC_NOTIFY;
        sub_param->notify = func;
        sub_param->subscribe = my_sub_callback;

        int err = bt_gatt_subscribe(conn, sub_param);
        
        if(err){
            LOG_DBG("ERROR IN THE SUBLOOP!");
        }
    }

    

    return 0;
}