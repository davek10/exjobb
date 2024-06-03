
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
#include "my_adv.h"
#include "db.h"
#include "mitm.h"
#include "my_uart.h"
#include "observer.h"
#include "errno.h"
#include "myutil.h"

LOG_MODULE_REGISTER(log1, APP_LOG_LEVEL);

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

static struct bt_conn_auth_cb auth_cb_display = {
	.passkey_display = auth_passkey_display,
	.passkey_entry = NULL,
	.cancel = auth_cancel,
};



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

	int my_naive_pow(int x, int n)
	{
		if (n == 0)
		{
			return 1;
		}
		else if (n == 1)
		{
			return x;
		}

		int xsqr = x * x;
		int res = 1;
		while (n > 1)
		{
			if (n % 2 == 0)
			{
				res *= xsqr;
				n = n / 2;
			}
			else
			{
				res *= x;
				n -= 1;
			}
		}
		return res;
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

	uint32_t my_str_to_uint(char *buf, size_t max_len)
	{
		size_t len = strnlen(buf, max_len);
		uint32_t res = 0;
		bool first = true;
		for (uint32_t i = 0; i < len; i++)
		{
			char c = buf[i];

			if (c < 48 || c > 57)
			{
				return -1;
			}
			LOG_DBG("c: %u, len: %u, i: %u, len-i: %u", (c - '0'), len, i, len - i);
			res += (c - '0') * my_naive_pow(10, len - i - 1);
		}
		return res;
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

	struct bt_hci_cp_le_set_random_address _bt_le_address = {
		.bdaddr = target_mitm_info.addr.a,
	};

	LOG_INF("Creating main connection to target ...\n");
	struct bt_conn_le_conn_param *my_param = BT_LE_CONN_PARAM_DEFAULT;
	struct bt_conn *_tmp_conn;
	char tmpp [BT_ADDR_LE_STR_LEN];
	bt_addr_le_to_str(get_my_target(),tmpp,sizeof(tmpp));
	LOG_DBG("target type: %u, data: %s",get_my_target()->type,tmpp);
	struct bt_conn_le_create_param *my_create_param = BT_CONN_LE_CREATE_PARAM(BT_CONN_LE_OPT_CODED,
																			  BT_GAP_SCAN_FAST_INTERVAL,
																			  BT_GAP_SCAN_FAST_INTERVAL);
	err = bt_conn_le_create(get_my_target(), my_create_param, my_param, &_tmp_conn);
	if(err){
		LOG_ERR("failed to connect to target err: %d ",err);
	}
	k_sem_take(&adv_sem, K_FOREVER);
	my_start_discovery();

	LOG_INF("main connection established waiting for discovery process ...\n");
	k_sem_take(&adv_sem, K_FOREVER);
	/*MY_MAN_BUF*/
	LOG_DBG("subscribing to attributes");
	err = my_adv_subscribe_to_all();

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
