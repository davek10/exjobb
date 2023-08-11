#include "adv.h"
#include <zephyr/types.h>
#include <zephyr/logging/log.h>
#include <zephyr/bluetooth/conn.h>
#include<zephyr/bluetooth/gatt.h>
#include "myutil.h"
#include <zephyr/bluetooth/uuid.h>

#define ALLOW_DISCOVERY


LOG_MODULE_DECLARE(log1, LOG_LEVEL_DBG);

struct k_sem disc_sem;
K_SEM_DEFINE(disc_sem, 2, 2);
K_SEM_DEFINE(adv_sem, 0, 1);

sys_slist_t my_attr_list = {NULL, NULL};
int my_attr_list_ctr;

struct bt_conn *main_conn = NULL;

struct bt_gatt_discover_params *chrc_params, *ccc_params;


void my_set_main_conn(struct bt_conn *new_conn){
    main_conn = new_conn;
}

struct bt_conn *my_get_main_conn()
{
    return main_conn;
}

static void my_ccc_callback(const struct bt_gatt_attr *attr, uint16_t value)
{
    return;
}

static size_t my_read_callback(struct bt_conn *conn,
                                      const struct bt_gatt_attr *attr,
                                      void *buf, uint16_t len,
                                      uint16_t offset)
{
    LOG_INF("trying to read: attribute with handle: %u \n", attr->handle);
    return 0;
}

static size_t my_write_callback(struct bt_conn *conn,
                                const struct bt_gatt_attr *attr,
                                const void *buf, uint16_t len,
                                uint16_t offset, uint8_t flags)
{
    LOG_INF("trying to write: attribute with handle: %u \n", attr->handle);
    return 0;
}

static void my_free_user_data(void *user_data){

        k_free(user_data);
    }

    static int free_attr_node(struct my_attr_node *attr_node)
{
    my_free_user_data(attr_node->attr.user_data);
    k_free(attr_node->attr.uuid);
    k_free(attr_node);
    return 0;
}


static uint16_t check_chrc_perm(uint16_t prop, struct bt_gatt_attr *attr)
{

    uint16_t perm = 0;
    for (int i = 0; i < 16; i++)
    {
        if (MY_CHECK_BIT(prop, i))
        {
            switch (i)
            {
            case 0:
                perm |= BT_GATT_CHRC_BROADCAST;
                break;
            case 1:
                perm |= BT_GATT_CHRC_READ;
                attr->read = my_read_callback;
                break;
            case 2:
                perm |= BT_GATT_CHRC_WRITE_WITHOUT_RESP;
                break;
            case 3:
                perm |= BT_GATT_CHRC_WRITE;
                attr->write = my_write_callback;
                break;
            case 4:
                perm |= BT_GATT_CHRC_NOTIFY;
                break;
            }
        }
    }
    return perm;
}



static int flush_attr_list(){

    struct my_attr_node *cn, *cns;
    struct bt_gatt_attr *attrs = k_malloc(my_attr_list_ctr * sizeof(struct bt_gatt_attr));

    int i = 0;
    LOG_DBG("starting to free stuff");
    SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&my_attr_list, cn, cns, node)
    {
        LOG_DBG("i = %i, ctr = %i",i,my_attr_list_ctr);

        char uuid_str[BT_UUID_STR_LEN];
        bt_uuid_to_str(cn->attr.uuid,uuid_str, BT_UUID_STR_LEN);
        LOG_DBG("adding attribute with uuid: %s   , handle: %u \n",uuid_str, cn->attr.handle);

        attrs[i] = cn->attr;
        i++;
        free_attr_node(cn);
    }
    LOG_DBG("done freeing stuff");
    sys_slist_init(&my_attr_list);
    LOG_DBG("INIT LIST");

    struct bt_gatt_service *_service = k_malloc(sizeof(struct bt_gatt_service));
    _service->attr_count = my_attr_list_ctr;
    _service->attrs = attrs;
    int err = bt_gatt_service_register(_service);

    SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&my_attr_list, cn, cns, node)

    my_attr_list_ctr = 0;

    return 0;
}

static int reset_attr_list(struct my_attr_node *attr_node)
{
    if(!sys_slist_is_empty(&my_attr_list)){
        flush_attr_list();
    }
    sys_slist_append(&my_attr_list, &attr_node->node);
    my_attr_list_ctr = 1;
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
        memcpy(&tmp->val, BT_UUID_128(_uuid)->val, BT_UUID_SIZE_128);
        return &tmp->uuid;
    }
}

static void * my_cpy_user_data(struct bt_gatt_discover_params *params, void * user_data)
{
    if (params->type == BT_GATT_DISCOVER_PRIMARY || params->type == BT_GATT_DISCOVER_SECONDARY)
    {
        struct bt_gatt_service_val *_data = user_data;

        struct bt_gatt_service_val *_data_cpy = k_malloc(sizeof(struct bt_gatt_service_val));
        _data_cpy->end_handle = _data->end_handle;
        struct bt_uuid *_uuid = my_cpy_uuid(_data->uuid);
        _data_cpy->uuid = _uuid;
        return _data_cpy;
    }
    
    else if(params->type == BT_GATT_DISCOVER_CHARACTERISTIC)
    {
        struct bt_gatt_chrc *_data = user_data;
        struct bt_gatt_chrc *_data_chrc_cpy = k_malloc(sizeof(struct bt_gatt_chrc));
        memcpy(_data_chrc_cpy, _data, sizeof(struct bt_gatt_chrc));
        _data_chrc_cpy->uuid = my_cpy_uuid(_data->uuid);
        return _data_chrc_cpy;
    }

    else if (params->type == BT_GATT_DISCOVER_STD_CHAR_DESC)
    {
        if (bt_uuid_cmp(params->uuid, BT_UUID_GATT_CCC) == 0)
        {
            struct _bt_gatt_ccc *_data = k_malloc(sizeof(struct _bt_gatt_ccc));
            _data->cfg_changed=my_ccc_callback;
            _data->cfg_match = NULL;
            _data->cfg_write = NULL;
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

static int my_add_service(struct bt_conn *conn, const struct bt_gatt_attr *attr, struct bt_gatt_discover_params *params)
{
    struct my_attr_node *node = k_malloc(sizeof(struct my_attr_node));

    struct bt_uuid *_uuid = my_cpy_uuid(attr->uuid);
    
    void *_user_data = my_cpy_user_data(params, attr->user_data);

    node->attr.uuid=_uuid;
    node->attr.user_data = _user_data;
    node->attr.handle = attr->handle;

    char uuid_str[BT_UUID_STR_LEN];
    bt_uuid_to_str(attr->uuid, uuid_str, sizeof(uuid_str));
    LOG_DBG("adding attrnode with uuid: %s,type: %u, handle: %u, ctr = %i \n",uuid_str,params->type,attr->handle, my_attr_list_ctr);

    if (params->type == BT_GATT_DISCOVER_PRIMARY || params->type == BT_GATT_DISCOVER_SECONDARY){

        node->attr.read = my_read_callback;
        node->attr.write = NULL;
        node->attr.perm = BT_GATT_PERM_READ;

        reset_attr_list(node);
        
        chrc_params->start_handle = params->start_handle+1;
        chrc_params->end_handle = ((struct bt_gatt_service_val *) attr->user_data)->end_handle;
        bt_gatt_discover(conn,chrc_params);

        ccc_params->start_handle = params->start_handle + 1;
        ccc_params->end_handle = ((struct bt_gatt_service_val *)attr->user_data)->end_handle;
        int err = bt_gatt_discover(conn, ccc_params);

        params->start_handle = ((struct bt_gatt_service_val *)attr->user_data)->end_handle;
        return 0;

    }else if (params->type == BT_GATT_DISCOVER_CHARACTERISTIC){
        node->attr.read = bt_gatt_attr_read_chrc;
        node->attr.write = NULL;
        node->attr.perm = BT_GATT_PERM_READ;

        struct bt_gatt_chrc *tmp = attr->user_data;
        struct my_attr_node *node2 = k_malloc(sizeof(struct my_attr_node));
        node2->attr.handle = tmp->value_handle;
        node2->attr.read = NULL;
        node2->attr.write = NULL;
        node2->attr.perm = check_chrc_perm(tmp->properties, &node2->attr);
        node2->attr.user_data = NULL;
        node2->attr.uuid = my_cpy_uuid(tmp->uuid);
        sys_slist_append(&my_attr_list, &node->node);
        sys_slist_append(&my_attr_list, &node2->node);
        my_attr_list_ctr+=2;
        return 0;
    }
    else if (params->type == BT_GATT_DISCOVER_STD_CHAR_DESC){
        if (bt_uuid_cmp(params->uuid, BT_UUID_GATT_CCC) == 0)
        {
            node->attr.perm = (BT_GATT_PERM_READ | BT_GATT_PERM_WRITE);
            node->attr.read = my_read_callback;
            node->attr.write = my_write_callback;

            sys_slist_append(&my_attr_list,&node->node);
            my_attr_list_ctr++;

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
            if(params->type == BT_GATT_DISCOVER_PRIMARY)
            {
                LOG_DBG("discover done \n");
                flush_attr_list();
                params->start_handle = -1;
                k_sem_give(&adv_sem);
                return BT_GATT_ITER_STOP;
            } else
            {
                k_sem_give(&disc_sem);
                return BT_GATT_ITER_STOP;
            }
    }

    int err = my_add_service(conn, attr, params);
    if (err < 0)
    {
        LOG_ERR("cant add service ERROR: %d \n", err);
    }
    if(params->type == BT_GATT_DISCOVER_PRIMARY){
        return BT_GATT_ITER_STOP;
    }
    return BT_GATT_ITER_CONTINUE;
}

int my_start_discovery(){
#ifdef ALLOW_DISCOVERY
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

        if (main_conn != NULL)
        {
        while(my_disc_params.start_handle > 0)
        {
            for (int i = 0; i < MY_ATTR_LIMIT; i++)
            {
                k_sem_take(&disc_sem, K_FOREVER);
            }
            int err = bt_gatt_discover(main_conn, &my_disc_params);
        }
    }else{
        LOG_ERR("failed to set main connection \n");
        return -1;
    }
#else
    k_sem_give(&adv_sem);
#endif
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

        LOG_INF("Connected to: %s, role: %s \n", addr, (my_info.role == BT_CONN_ROLE_CENTRAL ? "central" : "periphiral"));

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