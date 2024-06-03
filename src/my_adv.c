#include "my_adv.h"
#include <zephyr/types.h>
#include <zephyr/logging/log.h>
#include <zephyr/bluetooth/conn.h>
#include<zephyr/bluetooth/gatt.h>
#include "myutil.h"
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/logging/log_ctrl.h>
#include <stdlib.h>
#include "db.h"

#define ALLOW_DISCOVERY
//#define MYBLOCKREAD
#define MY_DISCOVER_CNT 3

LOG_MODULE_DECLARE(log1, APP_LOG_LEVEL);
#define CHECK_RULES

struct my_service_helper
{
    bool invalid_uuid;
    bool found_ccc;
    uint16_t last_ccc_handle;
    int last_ccc_indx;
    uint16_t last_value_handle;
    int last_value_indx;
    bool found_value;
};

struct k_sem disc_sem;
K_SEM_DEFINE(disc_sem, 0, K_SEM_MAX_LIMIT);
K_SEM_DEFINE(adv_sem, 0, 1);

struct k_mutex my_attr_mutex;
K_MUTEX_DEFINE(my_attr_mutex);

sys_slist_t my_attr_list = {NULL, NULL};

atomic_t my_subscribed = ATOMIC_INIT(0);

struct bt_conn *main_conn = NULL;

struct bt_gatt_discover_params *chrc_params, *ccc_params;

struct bt_gatt_service *_service;

uint16_t my_attr_list_ctr = 0;
int my_service_ctr = 0;

    static uint8_t
    tmp_func(const struct bt_gatt_attr *attr, uint16_t handle, void *user_data)
{

    if(!attr){
        return BT_GATT_ITER_STOP;
    }

    char uuid_str[BT_UUID_STR_LEN];
    bt_uuid_to_str(attr->uuid, uuid_str, BT_UUID_STR_LEN);
    
    LOG_DBG("found attr with uuid: %s, handle: %u", uuid_str, handle);

    if(bt_uuid_cmp(attr->uuid,BT_UUID_GATT_CCC) == 0){

        print_ccc_cfg_data(attr->user_data);
        
    }

    return BT_GATT_ITER_CONTINUE;
}

    static bool my_invalid_uuid(struct bt_uuid *uuid)
{
    bool val =  (bt_uuid_cmp(uuid, BT_UUID_GAP_APPEARANCE) == 0 || bt_uuid_cmp(uuid, BT_UUID_GAP) == 0 ||
    bt_uuid_cmp(uuid, BT_UUID_GATT_SC) == 0);

    char uuid_str[BT_UUID_STR_LEN];
    bt_uuid_to_str(uuid, uuid_str, BT_UUID_STR_LEN);
    
    return val;
}

void my_set_main_conn(struct bt_conn *new_conn){
    main_conn = new_conn;
}

struct bt_conn *my_get_main_conn()
{
    return main_conn;
}

void print_ccc_cfg_data(struct _bt_gatt_ccc *data){
    LOG_DBG("addr of cfg: %p", data);
    for(int i =0; i< 5; i++)
    {
        struct bt_gatt_ccc_cfg *tmp = &data->cfg[i];
        char addr_str[BT_ADDR_LE_STR_LEN];
        bt_addr_le_to_str(&tmp->peer, addr_str, BT_ADDR_LE_STR_LEN);
        LOG_DBG("ccc[%i] addr: %p id: %u, peer: %s, value: %u",i,tmp ,tmp->id, addr_str, tmp->value);
    }
}

ssize_t my_ccc_write_callback(struct bt_conn *conn,
                               const struct bt_gatt_attr *attr, const void *buf,
                               uint16_t len, uint16_t offset, uint8_t flags)
{
    char uuid_str[BT_UUID_STR_LEN];
    bt_uuid_to_str(attr->uuid, uuid_str, BT_UUID_STR_LEN);
    LOG_DBG("writing ccc callback handle: %u, uuid: %s", attr->handle, uuid_str);
    if(!attr->user_data){
        LOG_ERR("ERROR CCC USERDATA");
    }
    struct _bt_gatt_ccc *data = (struct _bt_gatt_ccc *)attr->user_data;
    LOG_DBG("ccc data value:  %u",data->value);
    print_ccc_cfg_data(data);

    ssize_t res = bt_gatt_attr_write_ccc(conn, attr, buf, len, offset, flags);
    print_ccc_cfg_data(data);
    return res;
}

static uint8_t my_ccc_callback(struct bt_conn * conn,
                                   struct bt_gatt_subscribe_params * params,
                                   const void *data, uint16_t len)
{
    LOG_DBG("recieved notification");
    if (!data)
    {
        LOG_ERR("ccc data error handle %u", params->value_handle);
        return BT_GATT_ITER_STOP;
    }
    
    const struct bt_gatt_attr *tmp_attr = my_db_write_entry(params->value_handle, data, len, false);
    uint16_t tmp_handle = my_get_char_handle(tmp_attr->handle);
    struct bt_gatt_attr *tmp_attr2 = my_db_get_attr(tmp_handle);

    LOG_DBG("attrhandle: %u, attr2handle: %u, tmp_handle %u, len: %u", tmp_attr->handle, tmp_attr2->handle,tmp_handle, len);
    LOG_HEXDUMP_DBG(data,len,"data:");

    char uuid_str[BT_UUID_STR_LEN];
    bt_uuid_to_str(tmp_attr2->uuid, uuid_str, BT_UUID_STR_LEN);
    struct bt_gatt_chrc *tmp_chrc = tmp_attr2->user_data;
    char uuid_str2[BT_UUID_STR_LEN];
    bt_uuid_to_str(tmp_chrc->uuid, uuid_str2, BT_UUID_STR_LEN); 
    LOG_DBG("attr2 uuid: %s, chrc uuid: %s, chrc valuehandle: %u", uuid_str, uuid_str2, tmp_chrc->value_handle);

    //bt_gatt_foreach_attr(1,0xffff,tmp_func,NULL);

    #ifdef CHECK_RULES
    void *new_ptr;
    int new_len;
    bool block = false;
    struct my_rule_res res = my_check_rules(1,tmp_attr2->handle);
    if(res.type == RULE_BLOCK){
        block = true;
    }else if(res.type == RULE_REPLACE){
        new_ptr = res.data;
        new_len = res.len;
    }
    else{
        new_ptr = data;
        new_len = len;
    }
    #endif
    if(atomic_test_bit(&my_subscribed,0)){
        LOG_INF("ccc update callback recieved: attribute with handle: %u \n", params->value_handle);
        if(!block){
            int err = bt_gatt_notify(NULL, tmp_attr2, new_ptr, new_len);
            if(err){
                LOG_ERR("gatt notify error: %i", err);
            }else{
                LOG_INF("user notified");
            }
        }else{
            LOG_INF("user not notified reason: communication blocked in direction : %i", 1);
        }

    }
    return BT_GATT_ITER_CONTINUE;
}

int my_adv_subscribe_to_all()
{

    int err = my_subscribe_to_all(main_conn, my_ccc_callback);
    return err;
}

static void my_ccc_changed(const struct bt_gatt_attr *attr, uint16_t value)
{
    LOG_INF("ccc callback: user wants to subscribe to attribute with handle: %u, value: %u \n", attr->handle, value);
    
    atomic_set(&my_subscribed, value);
    /*
    if (value == BT_GATT_CCC_NOTIFY){
        uint16_t value_handle = my_get_char_handle(attr->handle);
        struct bt_gatt_ccc *tmp = attr->user_data;
        struct bt_gatt_subscribe_params sub_params = {
            .ccc_handle = attr->handle,
            .notify = my_ccc_callback,
            .value_handle = value_handle,
            .value = BT_GATT_CCC_NOTIFY,

        };

    }*/
    LOG_DBG("ERROR");
    return;
}

    uint8_t my_read_callback(struct bt_conn * conn, uint8_t err,
                             struct bt_gatt_read_params * params,
                             const void *data, uint16_t length)
    {
        LOG_DBG("writing new value to db, length = %u", length);
        LOG_HEXDUMP_DBG(data, length, "read response callback: attribute with bytes:");

        my_db_write_entry(params->single.handle, data, length, false);
        return BT_GATT_ITER_STOP;
    }

    static size_t my_read_response_callback(struct bt_conn * conn,
                                            const struct bt_gatt_attr *attr,
                                            void *buf, uint16_t len,
                                            uint16_t offset)
    {
        LOG_INF("user trying to read: attribute with handle: %u len: %u\n", attr->handle, len);

        struct bt_conn_info info, main_info;
        bt_conn_get_info(conn, &info);
        bt_conn_get_info(main_conn, &main_info);
        LOG_DBG("conn_id = %u", info.id);
        LOG_DBG("main conn = %u, status = %u", main_info.id, main_info.state);


#ifdef MY_CALLBACK_ATTEMPT
/*     struct bt_gatt_read_params _read_params = {
        .func = my_read_callback,
        .handle_count = 1,
        .single = {
            .handle=attr->handle,
            .offset = 0,
        },
    }; */


   /*  struct bt_gatt_read_params *_read_params = k_malloc(sizeof(struct bt_gatt_read_params));
    memset(_read_params, 0, sizeof(struct bt_gatt_read_params));
    _read_params->func = my_read_callback;
    _read_params->handle_count = 1;
    _read_params->single.handle = attr->handle;
    _read_params->single.offset = 0; 
    int err = bt_gatt_read(main_conn, _read_params);
    */
   int length = 1;
    LOG_DBG("Sent read request!");
    bool wait = false;
    len = my_db_read_entry(attr->handle,buf,len,wait);
    //LOG_DBG("DONE WAITING!, tmp = %p", tmp);
    //memset(buf,0x01,1);
    return length;
#else

    int length = my_db_read_entry(attr->handle, buf, len, false);
    LOG_HEXDUMP_INF(buf,length,"data: ");
    void *new_ptr;
    int new_len;
    bool block = false;
    struct my_rule_res res = my_check_rules(1, attr->handle);
    if (res.type == RULE_BLOCK)
    {
        LOG_INF("user blocked from reading from handle :%u", attr->handle);
        block = true;
        return 0;
    }
    else if (res.type == RULE_REPLACE)
    {
        new_len = MIN(res.len,length);
        memcpy(buf, res.data,new_len);
        LOG_HEXDUMP_INF(buf, new_len, "replacing real data with: ");
        return new_len;
    }
    else
    {
        LOG_INF("sending data to user");
    return length;
    }

#endif
}

static void my_write_response_callback(struct bt_conn *conn, uint8_t err, struct bt_gatt_write_params *params)
{
    LOG_DBG("empty writecallback triggered");
    if(err){
        LOG_ERR("Error write callback code: %u", err);
    }
    return ;
};

static size_t my_write_callback(struct bt_conn *conn,
                                const struct bt_gatt_attr *attr,
                                const void *buf, uint16_t len,
                                uint16_t offset, uint8_t flags)
{
    LOG_INF("user trying to write to attribute with handle: %u \n", attr->handle);
    LOG_HEXDUMP_INF(buf, len, "data:");

    if(MY_CHECK_BIT(flags,1)){
        //bt_gatt_write_without_response(main_conn, attr->handle, buf, len,false);
    }else{

        void *new_ptr;
        int new_len;
        bool block = false;
        struct my_rule_res res = my_check_rules(0, attr->handle);
        if (res.type == RULE_BLOCK)
        {
            block = true;
        }
        else if (res.type == RULE_REPLACE)
        {
            new_ptr = res.data;
            new_len = res.len;
            LOG_HEXDUMP_INF(buf, new_len, "replacing real data with: ");
        }
        else
        {
            new_ptr = buf;
            new_len = len;
        }
        if(block){
            LOG_INF("user blocked from writing to target on handle :%u",attr->handle);
            return 0;
        }

        struct bt_gatt_write_params _write_params = {
            .handle = attr->handle,
            .data = new_ptr,
            .length = new_len,
            .offset = offset,
            .func = my_write_response_callback,
        };
        LOG_INF("writing to target");
        int err = bt_gatt_write(main_conn, &_write_params);
    }

    return len;
}

static void my_free_user_data(void *user_data){

    k_free(user_data);
}

    static int free_attr_node(struct my_attr_node *attr_node)
{
    LOG_DBG("freeing a node!");
    my_free_user_data(attr_node->attr.user_data);
    k_free(attr_node->attr.uuid);
    k_free(attr_node);
    return 0;
}


static struct my_char_perm check_chrc_perm(uint16_t prop, struct bt_gatt_attr *attr)
{
    uint16_t perm = 0;
    uint16_t new_prop = 0;
    for (int i = 0; i < 16; i++)
    {
        if (MY_CHECK_BIT(prop, i))
        {
            switch (i)
            {
            case 0:
                new_prop |= BT_GATT_CHRC_BROADCAST;
                break;
            case 1:
                new_prop |= BT_GATT_CHRC_READ;
                perm |= BT_GATT_PERM_READ;
                attr->read = my_read_response_callback;
                break;
            case 2:
                new_prop |= BT_GATT_CHRC_WRITE_WITHOUT_RESP;
                perm |= BT_GATT_PERM_WRITE;
                break;
            case 3:
                new_prop |= BT_GATT_CHRC_WRITE;
                perm |= BT_GATT_PERM_WRITE;
                attr->write = my_write_callback;
                break;
            case 4:
                new_prop |= BT_GATT_CHRC_NOTIFY;
                break;
            }
        }
    }
    LOG_DBG("char with handle= %u,   perm = %u",attr->handle, perm);
    return (struct my_char_perm){perm,new_prop};
}

static int my_empty_list()
{
    struct my_attr_node *cn, *cns;

    SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&my_attr_list, cn, cns, node)
    {

        free_attr_node(cn);
    }
    sys_slist_init(&my_attr_list);

    return 0;
}

static int my_attr_node_cmp(const void *c1, const void *c2){
    const struct bt_gatt_attr *attr1 = c1;
    const struct bt_gatt_attr *attr2 = c2;

    if(attr1->handle > attr2->handle){
        return 1;
    }
    else if (attr1->handle == attr2->handle)
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

static void my_init_service_helper(struct my_service_helper *sh){
    
    sh->invalid_uuid = false;
    sh->found_ccc = false;
    sh->found_value = false;
    sh->last_ccc_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE;
    sh->last_ccc_indx = -1;
    sh->last_value_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE;
    sh->last_value_indx = -1;
}

void my_print_attrs(struct bt_gatt_attr *attrs, uint16_t len){
    for(int i = 0; i< len; i++){
        struct bt_gatt_attr *attr = &attrs[i];
        char uuid_str[BT_UUID_STR_LEN];
        bt_uuid_to_str(attr->uuid, uuid_str,BT_UUID_STR_LEN);
        LOG_DBG("uuid: %s handle: %u",uuid_str, attr->handle);
    }
    LOG_DBG(" ");
}

static int flush_attr_list(){

    struct my_attr_node *cn, *cns;
    struct bt_gatt_attr *attrs = k_malloc(my_attr_list_ctr * sizeof(struct bt_gatt_attr));
    LOG_DBG("flushing list");

    int i = 0;
    SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&my_attr_list, cn, cns, node)
    {

        char uuid_str[BT_UUID_STR_LEN];
        bt_uuid_to_str(cn->attr.uuid,uuid_str, BT_UUID_STR_LEN);
        LOG_DBG("adding attribute with uuid: %s   , handle: %u \n",uuid_str, cn->attr.handle);
        attrs[i] = cn->attr;
        i++;
        /*
                if(cn->type == VALUE || cn->type == CHARACTERISTIC){
                    my_db_add_entry(cn->attr.handle,NULL,cn->len, &attrs[i]);
                }
                i++;
                k_free(cn);
                */
    }

    my_print_attrs(attrs, my_attr_list_ctr);
    qsort(attrs,my_attr_list_ctr,sizeof(struct bt_gatt_attr),my_attr_node_cmp);
    my_print_attrs(attrs, my_attr_list_ctr);

    uint16_t start_handle = 0;

    struct my_service_helper sh;
    my_init_service_helper(&sh);
    int ctr = 0;
    for(int j = my_attr_list_ctr-1; j >= 0 ; j-- ){
        struct bt_gatt_attr *tmp_attr = &attrs[j];
        ctr++;
        if (bt_uuid_cmp(tmp_attr->uuid, BT_UUID_GATT_PRIMARY) == 0 || bt_uuid_cmp(tmp_attr->uuid, BT_UUID_GATT_SECONDARY) == 0)
        {

            if(!sh.invalid_uuid){
                _service = k_malloc(sizeof(struct bt_gatt_service));
                _service->attr_count = ctr;
                _service->attrs = tmp_attr;
                

                char uuid_str[BT_UUID_STR_LEN];
                bt_uuid_to_str(tmp_attr->uuid, uuid_str,BT_UUID_STR_LEN);
                LOG_DBG("register uuid: %s handle: %u, counter: %d",uuid_str, tmp_attr->handle, ctr);


                int err = bt_gatt_service_register(_service);
                LOG_DBG("err = %d", err);
            }
            my_init_service_helper(&sh);
            ctr = 0;
        } else if (bt_uuid_cmp(tmp_attr->uuid, BT_UUID_GATT_CCC) == 0){
            sh.found_ccc = true;
            sh.last_ccc_handle = tmp_attr->handle;
            sh.last_ccc_indx = j;

        }else if (bt_uuid_cmp(tmp_attr->uuid, BT_UUID_GATT_CHRC) == 0){
            if(sh.found_ccc && sh.last_ccc_handle != BT_ATT_LAST_ATTRIBUTE_HANDLE){
                
                if(!sh.invalid_uuid){
                    struct bt_gatt_chrc *tmp_chrc = tmp_attr->user_data;
                    my_add_ccc_entry(sh.last_ccc_handle,tmp_attr->handle,tmp_chrc->value_handle);
                    my_db_add_entry(tmp_attr->handle,NULL,0,tmp_attr);
                }
                sh.found_ccc = false;
                sh.last_ccc_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE;
            }
        }else{
            if(my_invalid_uuid(tmp_attr->uuid)){
                char uuid_str[BT_UUID_STR_LEN];
                bt_uuid_to_str(tmp_attr->uuid, uuid_str, BT_UUID_STR_LEN);
                LOG_DBG("found invalid uuid: %s handle: %u",uuid_str, tmp_attr->handle);
                sh.invalid_uuid = true;
            }else{
                sh.found_value = true;
                my_db_add_entry(tmp_attr->handle,NULL,0,tmp_attr);
            }
        
        }
    }

    return 0;
}

static int reset_attr_list()
{
    if(!sys_slist_is_empty(&my_attr_list)){
            my_empty_list();
    }

    return 0;
}

static struct bt_uuid* my_cpy_uuid(struct bt_uuid *_uuid)
{

    if (_uuid->type == BT_UUID_TYPE_16)
    {
        struct bt_uuid_16 *tmp = k_malloc(sizeof(struct bt_uuid_16));
        memcpy(&tmp->uuid, _uuid, sizeof(struct bt_uuid));
        memcpy(&tmp->val, &BT_UUID_16(_uuid)->val, BT_UUID_SIZE_16);
        return &tmp->uuid;
    }
    else if(_uuid->type == BT_UUID_TYPE_32){
        struct bt_uuid_32 *tmp = k_malloc(sizeof(struct bt_uuid_32));
        memcpy(&tmp->uuid, _uuid, sizeof(struct bt_uuid));
        memcpy(&tmp->val, &BT_UUID_32(_uuid)->val, BT_UUID_SIZE_32);
        return &tmp->uuid;
    }
    else if(_uuid->type == BT_UUID_TYPE_128){
        struct bt_uuid_128 *tmp = k_malloc(sizeof(struct bt_uuid_128));
        memcpy(&tmp->uuid, _uuid, sizeof(struct bt_uuid));
        memcpy(tmp->val, BT_UUID_128(_uuid)->val, BT_UUID_SIZE_128);
        //bt_uuid_create(&tmp->uuid, &BT_UUID_128(_uuid)->val, BT_UUID_SIZE_128);
        return &tmp->uuid;
    }
}

static void * my_cpy_user_data(struct bt_gatt_discover_params *params, void * user_data)
{
    if (params->type == BT_GATT_DISCOVER_PRIMARY || params->type == BT_GATT_DISCOVER_SECONDARY)
    {
        struct bt_gatt_service_val *_data = user_data;
        struct bt_uuid *_uuid = my_cpy_uuid(_data->uuid);
        return _uuid;
    }
    else if(params->type == BT_GATT_DISCOVER_CHARACTERISTIC)
    {
        struct bt_gatt_chrc *_data = user_data;
        struct bt_gatt_chrc *_data_chrc_cpy = k_malloc(sizeof(struct bt_gatt_chrc));
        //memcpy(_data_chrc_cpy, _data, sizeof(struct bt_gatt_chrc));
        
        _data_chrc_cpy->properties = _data->properties;
        _data_chrc_cpy->value_handle = _data->value_handle;
        struct bt_uuid *tmp = my_cpy_uuid(_data->uuid);
        _data_chrc_cpy->uuid = tmp;
        struct bt_uuid_128 *a = BT_UUID_128(_data->uuid);
        struct bt_uuid_128 *b = BT_UUID_128(_data_chrc_cpy->uuid);
        struct bt_uuid_128 *c = BT_UUID_128(tmp);
        return _data_chrc_cpy;
    }
    else if (params->type == BT_GATT_DISCOVER_STD_CHAR_DESC)
    {
        if (bt_uuid_cmp(params->uuid, BT_UUID_GATT_CCC) == 0)
        {
            LOG_DBG("CCC userdata created");
            struct _bt_gatt_ccc *_data = k_malloc(sizeof(struct _bt_gatt_ccc));
            memset(_data,0,sizeof(struct _bt_gatt_ccc));
            _data->cfg_changed = my_ccc_changed;
            _data->cfg_match = NULL;
            _data->cfg_write = NULL;
            LOG_DBG("AT CREATION");
            print_ccc_cfg_data(_data);
            return _data;
        }
        else if (bt_uuid_cmp(params->uuid, BT_UUID_GATT_CEP) == 0)
        {
            return NULL;
        }
        else
        {
            return NULL;
        }
    }
    else
    {
        return NULL;
    }
}

static void my_attr_list_append(struct my_attr_node *node){

    k_mutex_lock(&my_attr_mutex,K_FOREVER);
    sys_slist_append(&my_attr_list, &node->node);
    my_attr_list_ctr++;
    k_mutex_unlock(&my_attr_mutex);
}

static int my_add_service(struct bt_conn *conn, const struct bt_gatt_attr *attr, struct bt_gatt_discover_params *params)
{

    struct my_attr_node *node = k_malloc(sizeof(struct my_attr_node));
    struct bt_uuid *_uuid = my_cpy_uuid(attr->uuid);
    void *_user_data = my_cpy_user_data(params, attr->user_data);

    node->attr.uuid=_uuid;
    node->attr.user_data = _user_data;
    node->attr.handle = attr->handle;
    //node->attr.handle = 0;

    char uuid_str[BT_UUID_STR_LEN];

    if (params->type == BT_GATT_DISCOVER_PRIMARY || params->type == BT_GATT_DISCOVER_SECONDARY)
    {

        node->attr.read = bt_gatt_attr_read_service;
        node->attr.write = NULL;
        node->attr.perm = BT_GATT_PERM_READ;

        struct uuid *ttmp = node->attr.user_data; 
        bt_uuid_to_str(ttmp, uuid_str, sizeof(uuid_str));
        my_attr_list_append(node);
        return 0;

    }else if (params->type == BT_GATT_DISCOVER_CHARACTERISTIC)
    {
        node->attr.read = bt_gatt_attr_read_chrc;
        node->attr.write = NULL;
        node->attr.perm = BT_GATT_PERM_READ;
        node->type = CHARACTERISTIC;
        node->len = MY_DEFAULT_LEN;

        struct bt_gatt_chrc *tmp = attr->user_data;

        struct my_attr_node *node2 = k_malloc(sizeof(struct my_attr_node));
        if(!node2){
            LOG_ERR("COULD NOT ALLOCATE MEMORY");
        }
        //node2->attr.handle = tmp->value_handle;
        node2->attr.handle = tmp->value_handle;
        node2->attr.read = NULL;
        node2->attr.write = NULL;
        node2->type = VALUE;
        node2->len = MY_DEFAULT_LEN;
        struct my_char_perm tmp_perms = check_chrc_perm(tmp->properties, &node2->attr);
        node2->attr.perm = tmp_perms.perm;
        node2->attr.user_data = NULL;
        node2->attr.uuid = my_cpy_uuid(tmp->uuid);
        my_attr_list_append(node);
        my_attr_list_append(node2);
        return 0;
    }
    else if (params->type == BT_GATT_DISCOVER_STD_CHAR_DESC)
    {
        if (bt_uuid_cmp(params->uuid, BT_UUID_GATT_CCC) == 0)
        {
            node->attr.perm = (BT_GATT_PERM_READ | BT_GATT_PERM_WRITE);
            node->attr.read = bt_gatt_attr_read_ccc;
            //node->attr.write = my_ccc_write_callback;
            node->attr.write = bt_gatt_attr_write_ccc;

            my_attr_list_append(node);
            return 0;

        }
        else if (bt_uuid_cmp(params->uuid, BT_UUID_GATT_CEP) == 0)
        {
            return -1;
        }
        else
        {
            return -1;
        }
    }

        return 0;
}

static uint8_t my_discover_func(struct bt_conn *conn,
                                const struct bt_gatt_attr *attr,
                                struct bt_gatt_discover_params *params)
{
    if (attr == NULL)
    {
            LOG_DBG("%u gives sema",params->type);
            k_sem_give(&disc_sem);
            return BT_GATT_ITER_STOP;
    }
    
    int err = my_add_service(conn, attr, params);

    char uuid_str[BT_UUID_STR_LEN];
    bt_uuid_to_str(attr->uuid, uuid_str, BT_UUID_STR_LEN);

    if (err < 0)
    {
        LOG_ERR("cant add service ERROR: %d \n", err);
        return err;
    }
    return BT_GATT_ITER_CONTINUE;
}

int my_start_discovery()
{
    struct bt_gatt_discover_params my_disc_params =
        {
            .uuid = NULL,
            .type = BT_GATT_DISCOVER_PRIMARY,
            .start_handle = BT_ATT_FIRST_ATTRIBUTE_HANDLE,
            .end_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE,
            .func = my_discover_func,
        };
    struct bt_gatt_discover_params tmp_chrc_params =
        {
            .uuid = NULL,
            .type = BT_GATT_DISCOVER_CHARACTERISTIC,
            .start_handle = BT_ATT_FIRST_ATTRIBUTE_HANDLE,
            .end_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE,
            .func = my_discover_func,
        };
    struct bt_gatt_discover_params tmp_ccc_params =
        {
            .uuid = BT_UUID_GATT_CCC,
            .type = BT_GATT_DISCOVER_STD_CHAR_DESC,
            .start_handle = BT_ATT_FIRST_ATTRIBUTE_HANDLE,
            .end_handle = BT_ATT_LAST_ATTRIBUTE_HANDLE,
            .func = my_discover_func,
        };


    chrc_params = &tmp_chrc_params;
    ccc_params = &tmp_ccc_params;

    if (!main_conn)
    {
        LOG_ERR("failed to set main connection \n");
        return -1;
    }





    int err = bt_gatt_discover(main_conn, &my_disc_params);
    err = bt_gatt_discover(main_conn, &tmp_chrc_params);
    err = bt_gatt_discover(main_conn, &tmp_ccc_params);

    LOG_DBG("sent all discovers");

    for(int i = 0; i< MY_DISCOVER_CNT;i++){
        k_sem_take(&disc_sem,K_FOREVER);
        LOG_DBG("got %d sema",i);
    }

    flush_attr_list();
    LOG_DBG("reset list");
    reset_attr_list();

    k_sem_give(&adv_sem);
    return 0;
}

static void connected(struct bt_conn * conn, uint8_t err)
{
    struct bt_conn_info my_info;

    if (err)
    {
        LOG_ERR("Connection failed (err %u)\n", err);
        return;
    }
    bt_conn_get_info(conn, &my_info);

    char addr[BT_ADDR_LE_STR_LEN];
    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

    LOG_INF("Connected to: %s, id: %u, role: %s \n", addr, my_info.id, (my_info.role == BT_CONN_ROLE_CENTRAL ? "central" : "periphiral"));

    if (my_info.role == BT_CONN_ROLE_CENTRAL)
    {
        main_conn = conn;
        k_sem_give(&adv_sem);
        return;
    }
    else
    {
        return;
    }
}

static void disconnected(struct bt_conn * conn, uint8_t reason)
{
    char addr[BT_ADDR_LE_STR_LEN];
    bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));
    LOG_INF("Disconnected to : %s (reason %u)\n",addr,reason);
}

BT_CONN_CB_DEFINE(conn_callbacks) = {
    .connected = connected,
    .disconnected = disconnected,
};