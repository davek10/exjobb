#include "db.h"
#include <zephyr/logging/log.h>

LOG_MODULE_DECLARE(log1, LOG_LEVEL_DBG);

static sys_slist_t my_db = {NULL, NULL};
static sys_slist_t my_ccc_list = {NULL, NULL};

int my_db_add_entry(uint16_t handle, const void *data, uint16_t len, struct bt_gatt_attr *attr)
{
    LOG_DBG("adding entry with handle: %u", handle);
    struct my_db_node *node = k_malloc(sizeof(struct my_db_node));
    struct my_db_entry *entry = &node->data;
    entry->data = k_malloc(len);
    entry->len = len;
    entry->handle = handle;
    entry->attr = attr;
    k_sem_init(&node->sema,0,1);
    
    if(data == NULL){
        memset(entry->data, 0, len);
    }else{
        memcpy(entry->data, data, len);
    }
    sys_slist_append(&my_db, &node->node);
    return 0;
}

const struct bt_gatt_attr *my_db_read_entry(uint16_t handle, void *buffer, uint16_t len, bool wait)
{
    LOG_DBG("in read db");
    struct my_db_node *cn;
    SYS_SLIST_FOR_EACH_CONTAINER(&my_db, cn, node){
        LOG_DBG("current handle: %u, looking for handle: %u",cn->data.handle, handle);
        if(cn->data.handle == handle){
            int err = 0;
            if (wait)
            {
                LOG_DBG("starting to wait for handle %u ", handle);
                err = k_sem_take(&cn->sema, K_FOREVER);
            }

            memcpy(buffer, cn->data.data, len);
            return cn->data.attr;
        }
    }

    return NULL;
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
            memcpy(cn->data.data, buffer, len);
            if(wake){
                LOG_DBG("waking handle %u", handle);
                k_sem_give(&cn->sema);
            }

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

int my_add_ccc_entry(uint16_t ccc_handle, uint16_t char_handle){
    struct my_ccc_node *node = k_malloc(sizeof(struct my_ccc_node));
    node->data.ccc_handle = ccc_handle;
    node->data.char_handle = char_handle;

    sys_slist_append(&my_ccc_list, node);
    return 0;
}

uint16_t my_get_char_handle(uint16_t ccc_handle){

    struct my_ccc_node *cn;
    SYS_SLIST_FOR_EACH_CONTAINER(&my_ccc_list, cn, node)
    {

        if (cn->data.ccc_handle == ccc_handle)
        {
            return cn->data.char_handle;
        }
    }
    return 0;
}

int my_remove_ccc_entry(uint16_t ccc_handle){

    return 0;
}