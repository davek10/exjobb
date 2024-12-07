/*
 * Contains code inspired by and/or copied and modified from NRF SDK Observer demo:
 * https://github.com/zephyrproject-rtos/zephyr/tree/main/samples/bluetooth/observer
 *
 * Original copyright:
 *
 * Copyright (c) 2022 Nordic Semiconductor ASA
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "observer.h"
#include <zephyr/bluetooth/uuid.h>
#include <zephyr/logging/log.h>
//#include <bluetooth/services/lbs.h>
#include <zephyr/sys/slist.h>
#include "myutil.h"
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/hci.h>
#include <string.h>
#include <zephyr/bluetooth/addr.h>
#include "mitm.h"

#define MY_BT_DATA_SOL

LOG_MODULE_DECLARE(log1, APP_LOG_LEVEL);

//atomic_t my_obs_disp = ATOMIC_INIT(0);

struct my_block_node {
	bt_addr_le_t addr;
	char text[MY_OBS_BLOCK_STR_LEN];
};

int my_obs_blocklist_ctr = 0;
struct my_block_node my_obs_blocklist[MY_OBS_BLOCKLIST_CNT];

//#define MY_DEBUG

static void device_found(const bt_addr_le_t *addr, int8_t rssi, uint8_t type,
			 struct net_buf_simple *ad)
{
	char addr_str[BT_ADDR_LE_STR_LEN];
	bt_addr_le_to_str(addr, addr_str, sizeof(addr_str));
	
	#ifdef MY_DEBUG
	LOG_INF("Device found: %s (RSSI %d), type %u, AD data len %u\n",
			addr_str, rssi, type, ad->len);
	#endif
}

#if defined(CONFIG_BT_EXT_ADV)
static bool data_cb(struct bt_data *data, void *user_data)
{
	char *name = user_data;
	uint8_t len;

	switch (data->type) {
	case BT_DATA_NAME_SHORTENED:
	case BT_DATA_NAME_COMPLETE:
		len = MIN(data->data_len, NAME_LEN - 1);
		(void)memcpy(name, data->data, len);
		name[len] = '\0';
		return false;
	default:
		return true;
	}
}

static const char *phy2str(uint8_t phy)
{
	switch (phy) {
	case BT_GAP_LE_PHY_NONE: return "No packets";
	case BT_GAP_LE_PHY_1M: return "LE 1M";
	case BT_GAP_LE_PHY_2M: return "LE 2M";
	case BT_GAP_LE_PHY_CODED: return "LE Coded";
	default: return "Unknown";
	}
}

bool my_obs_check_blocklist(const bt_addr_le_t *addr){

	if(my_obs_blocklist_ctr == 0) return false;

	for(int i = 0; i< my_obs_blocklist_ctr; i++){
		if(bt_addr_le_cmp(&my_obs_blocklist[i].addr,addr) == 0){
			return true;
		}
	}
	return false;
}

int my_obs_print_blocklist(){
	for (int i = 0; i < my_obs_blocklist_ctr; i++)
	{
		LOG_INF("%s",my_obs_blocklist[i].text);
		k_msleep(50);
	}
	LOG_DBG("last obj printed");
	return 0;
}

int my_obs_add_to_blocklist(bt_addr_le_t *addr, const char* text){

	if(my_obs_blocklist_ctr == MY_OBS_BLOCKLIST_CNT) return -1;

	my_obs_blocklist[my_obs_blocklist_ctr].addr = *addr;
	strncpy(my_obs_blocklist[my_obs_blocklist_ctr].text,text,MY_OBS_BLOCK_STR_LEN);
	my_obs_blocklist_ctr++;
	return 0;	
}

void my_clear_block(){
	
	my_obs_blocklist_ctr = 0;
}

static void scan_recv(const struct bt_le_scan_recv_info *info,
		      struct net_buf_simple *buf)
{
	char le_addr[BT_ADDR_LE_STR_LEN];
	char name[NAME_LEN];
	uint8_t data_status;
	uint16_t data_len;
	//info->primary_phy;

	(void)memset(name, 0, sizeof(name));

	data_len = buf->len;
	bt_data_parse(buf, data_cb, name);

	data_status = BT_HCI_LE_ADV_EVT_TYPE_DATA_STATUS(info->adv_props);

	bt_addr_le_to_str(info->addr, le_addr, sizeof(le_addr));


	if(my_obs_check_blocklist(info->addr) == 0)
	{
		char text[MY_OBS_BLOCK_STR_LEN];
		snprintk(&text,MY_OBS_BLOCK_STR_LEN,"[DEVICE]: %s, AD evt type %u, Tx Pwr: %i, RSSI %i "
		"Data status: %u, AD data len: %u Name: %s "
		"C:%u S:%u D:%u SR:%u E:%u Pri PHY: %s, Sec PHY: %s, "
		"Interval: 0x%04x (%u ms), SID: %u\n",
		le_addr, info->adv_type, info->tx_power, info->rssi,
		data_status, data_len, name,
		(info->adv_props & BT_GAP_ADV_PROP_CONNECTABLE) != 0,
		(info->adv_props & BT_GAP_ADV_PROP_SCANNABLE) != 0,
		(info->adv_props & BT_GAP_ADV_PROP_DIRECTED) != 0,
		(info->adv_props & BT_GAP_ADV_PROP_SCAN_RESPONSE) != 0,
		(info->adv_props & BT_GAP_ADV_PROP_EXT_ADV) != 0,
		phy2str(info->primary_phy), phy2str(info->secondary_phy),
		info->interval, info->interval * 5 / 4, info->sid);

		my_obs_add_to_blocklist(info->addr,text);
	}
	
	
}

	static struct bt_le_scan_cb scan_callbacks = {
		.recv = scan_recv,
};

static bool my_data_cb(struct bt_data *data, void *user_data){

	struct my_callback_struct *cbs = user_data;
	struct my_mitm_info* mitm_info = cbs->mitm_info;
	uint8_t len = data->data_len;
	bool is_bt_data = false;

	void *_data_ptr = NULL;
	char str_uuid[BT_UUID_STR_LEN];

	switch (data->type)
	{
	case BT_DATA_FLAGS:
		mitm_info->flags = *data->data;
		_data_ptr = &(mitm_info->flags);
		break;
	case BT_DATA_NAME_SHORTENED:
	case BT_DATA_NAME_COMPLETE:
		mitm_info->fullname = data->type == BT_DATA_NAME_COMPLETE;
		len = MIN(data->data_len, NAME_LEN - 1);
		(void)memcpy(mitm_info->name, data->data, len);
		mitm_info->name[len] = '\0';
		mitm_info->name_len = len;
		_data_ptr = &(mitm_info->name);
		break;

	case BT_DATA_MANUFACTURER_DATA:
		memcpy(&mitm_info->man_data, data->data, data->data_len);
		_data_ptr = &(mitm_info->man_data);
		break;

	case BT_DATA_GAP_APPEARANCE:
		LOG_DBG("FOUND APPEARANCE!!!! data: %u, len: %u", *((uint16_t *)(data->data)), data->data_len);
		memcpy(&mitm_info->appearance, data->data, data->data_len);
		_data_ptr = &(mitm_info->appearance);
		break;

	case BT_DATA_UUID16_ALL:
#ifdef MY_BT_DATA_SOL
		_data_ptr = data;
		is_bt_data = true;
	#else
		bt_uuid_create(&mitm_info->uuid16.uuid, data->data, data->data_len);
		bt_uuid_to_str((struct bt_uuid *)&mitm_info->uuid16, str_uuid, BT_UUID_STR_LEN);
		_data_ptr = &(mitm_info->uuid16.val);
	#endif
		break;
	case BT_DATA_UUID32_ALL:
#ifdef MY_BT_DATA_SOL
		_data_ptr = data;
		is_bt_data = true;
#else
		bt_uuid_create(&mitm_info->uuid32.uuid, data->data, data->data_len);
		bt_uuid_to_str((struct bt_uuid *)&mitm_info->uuid32, str_uuid, BT_UUID_STR_LEN);

		_data_ptr = &(mitm_info->uuid32.val);
#endif
		break;

	case BT_DATA_UUID128_ALL:

	#ifdef MY_BT_DATA_SOL
		_data_ptr = data;
		is_bt_data = true;
	#else
		bt_uuid_create(&mitm_info->uuid128.uuid, data->data, data->data_len);
		bt_uuid_to_str((struct bt_uuid *) &mitm_info->uuid128, str_uuid, BT_UUID_STR_LEN);

		_data_ptr = &(mitm_info->uuid128.val);

		// LOG_INF("uuid = %s \n", str_uuid);
		// LOG_INF("");
	#endif
		break;
	default:
		LOG_DBG("unhandeled type: %u, len: %u\n", data->type, len);
		_data_ptr = data->data;
		break;
	}
	if(_data_ptr != NULL){
		my_mitm_add_ad(data->type, _data_ptr, len, cbs->is_sr, is_bt_data);
	}
	return true;
}


static void my_scan_rcv_cb(const struct bt_le_scan_recv_info *info,
							struct net_buf_simple *buf)
{
	if (get_my_target_set() && (!get_my_mitm_started()))
	{
		const bt_addr_le_t * target = get_my_target();

		const char target_s[BT_ADDR_LE_STR_LEN], info_addr_s[BT_ADDR_LE_STR_LEN];

		if(bt_addr_le_cmp(get_my_target(),info->addr) == 0){

			bool my_scan_resp = false;
			bool my_ext_adv = false;

			switch (info->adv_type)
			{
	
			case BT_GAP_ADV_TYPE_SCAN_RSP:
			LOG_DBG("is scan resp");
				my_scan_resp = true;
				break;
			case BT_GAP_ADV_TYPE_EXT_ADV:
				my_ext_adv = true;
				target_mitm_info.ext_adv = true;
				break;
			default:
				break;
			}
			
			struct my_callback_struct cb_info =
			{
				.mitm_info = &target_mitm_info,
				.is_sr = my_scan_resp,
			};

		bt_data_parse(buf, my_data_cb, &cb_info);
		LOG_DBG("data parsed");

		//bt_data_parse(buf, my_data_cb, &target_mitm_info);
		bt_addr_le_copy(&target_mitm_info.addr, info->addr);
		bt_addr_le_to_str(&target_mitm_info.addr, target_mitm_info.addr_str, sizeof(target_mitm_info.addr_str));
		target_mitm_info.phy1 = info->primary_phy;
		target_mitm_info.phy2 = info->secondary_phy;
		target_mitm_info.coded_phy = (info->primary_phy == BT_GAP_LE_PHY_CODED &&
									  (info->secondary_phy == BT_GAP_LE_PHY_CODED || info->secondary_phy == BT_GAP_LE_PHY_NONE));

		LOG_DBG("primary phy : %u, sec phy: %u, is_coded: %u", info->primary_phy, info->secondary_phy, my_mitm_get_is_coded());

		// my_print_mitm_info(&target_mitm_info);
		
		if(my_scan_resp){
			target_mitm_info.sd_amount++;
		}else{
			target_mitm_info.ad_amount++;
		}

		int err = my_activate_mitm();
		if (err)
		{
			LOG_ERR("Start mitm failed (err %d)\n", err);
		}
		}
	}
}

static struct bt_le_scan_cb my_scan_callbacks = {
	.recv = my_scan_rcv_cb,
};

#endif /* CONFIG_BT_EXT_ADV */
int observer_start(void)
{
	struct bt_le_scan_param scan_param = {
		.type = BT_LE_SCAN_TYPE_ACTIVE,
		.options = BT_LE_SCAN_OPT_CODED,
		.interval = BT_GAP_SCAN_FAST_INTERVAL,
		.window = BT_GAP_SCAN_FAST_WINDOW,
	};
	int err;

#if defined(CONFIG_BT_EXT_ADV)
	bt_le_scan_cb_register(&scan_callbacks);
	bt_le_scan_cb_register(&my_scan_callbacks);
	LOG_INF("Registered scan callbacks\n");
#endif /* CONFIG_BT_EXT_ADV */

	err = bt_le_scan_start(&scan_param, NULL);
	if (err) {
		LOG_ERR("Start scanning failed (err %d)\n", err);
		return err;
	}
	LOG_INF("Started scanning...\n");

	return 0;
}