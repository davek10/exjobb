/*
 * Copyright (c) 2022 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <zephyr/bluetooth/bluetooth.h>
#include "observer.h"
#include "mitm.h"
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include<zephyr/bluetooth/hci.h>
#include<zephyr/bluetooth/buf.h>
#include"adv.h"
#include "my_uart.h"
#include <string.h>
#include "db.h"

LOG_MODULE_REGISTER(log1, LOG_LEVEL_DBG);

enum command{
	LIST_HANDLES,
	LIST_CONNECTIONS,
	BLOCK,
	ALTER,
	EXIT,
	ERROR,
	TARGET
};


void lst_handle_cb(uint16_t handle,struct bt_gatt_attr *attr, void *data){
	
	char uuid_str[BT_UUID_STR_LEN];
	bt_uuid_to_str(attr->uuid, uuid_str, BT_UUID_STR_LEN);
	LOG_DBG("handle: %u, uuid: %s", handle, uuid_str);
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


int my_naive_pow(int x, int n){
	if(n == 0 ){
		return 1;
	}
	else if(n ==1 ){
		return x;
	}

	int xsqr = x*x;
	int res = 1;
	while(n > 1){
		if(n % 2 == 0){
			res*=xsqr;
			n = n/2;
		} else{
			res*=x;
			n-=1;
		}
	}
	return res;
}

int my_str_to_int(char *buf, size_t max_len){
	size_t len = strnlen(buf,max_len);
	int res = 0;
	bool first = true;
	for(int i = 0; i< len; i++){
		char c = buf[i];

		if(c < 48 || c > 57){
			return -1;
		}
		res+= (c-'0')* my_naive_pow(10,len-i);
	}
	return res;
}

enum command handle_command(char *buf){
	char *tmp;
	char *iter = strtok_r(buf," ",&tmp);

	if (strncmp(iter, "list", sizeof("list")) == 0)
	{
		LOG_DBG("in list");
		iter = strtok_r(buf,NULL,&tmp);
		if (strncmp(iter, "handles", sizeof("handles")) == 0)
		{
			return LIST_HANDLES;
		}
		else if (strncmp(iter, "connections", sizeof("connections")) == 0){
			return LIST_CONNECTIONS;
		}
		return ERROR;
	}
	else if (strncmp(iter, "exit", sizeof("exit")) == 0)
	{

		return EXIT;
	}
	else if (strncmp(iter, "block", sizeof("block")) == 0)
	{
		iter = strtok_r(buf, NULL, &tmp);
		int nr = my_str_to_int(iter, UART_MSG_SIZE);
		my_add_rule(0,nr,0,0);
		return BLOCK;
	}
	else if (strncmp(iter, "set_target", sizeof("set_target")) == 0)
	{
		iter = strtok_r(buf, NULL, &tmp);
		char addr[BT_ADDR_LE_STR_LEN];
		strncpy(addr,iter,BT_ADDR_LE_STR_LEN);
		LOG_DBG("addr = %s",addr);
		iter = strtok_r(buf, NULL, &tmp);
		char type[sizeof("random")];
		strncpy(type, iter, sizeof(type));
		LOG_DBG("type = %s", type);
		set_my_target(addr,type);
		return TARGET;
	}
		/* 	else if (strcmp(iter, "change"))
			{
				iter = strtok(buf, NULL, &tmp);
				int nr = my_str_to_int(iter, UART_MSG_SIZE);
				my_add_rule(0, nr, 0, 0);
				return BLOCK;
			} */
		else
		{
			return ERROR;
		}
	}

void main(void)
{
	int err;

	LOG_INF("Starting Observer Demo\n");

	my_init_mitm();

	/* Initialize the Bluetooth Subsystem */
	err = bt_enable(NULL);
	if (err) {
		LOG_ERR("Bluetooth init failed (err %d)\n", err);
		return;
	}

	err = observer_start();
	if (err){
		LOG_ERR("Bluetooth observer failed (err %d)\n", err);
		return;
	}

	err = set_my_target("F7:E1:36:7C:5B:AB","random");


	LOG_INF("waiting for sema");

	k_sem_take(&target_sem, K_FOREVER);
	
	LOG_INF("stopping scanning");
	err = bt_le_scan_stop();
	if (err)
	{
		LOG_ERR("Bluetooth stop scanning failed (err %u)\n", err);
		return;
	}

	struct bt_hci_cp_le_set_random_address _bt_le_address = {
		.bdaddr = target_mitm_info.addr.a,
	};
	

	LOG_INF("Creating main connection ...\n");
	struct bt_conn_le_conn_param *my_param = BT_LE_CONN_PARAM_DEFAULT;
	struct bt_conn * _tmp_conn;
	bt_conn_le_create(get_my_target(), BT_CONN_LE_CREATE_CONN, my_param, &_tmp_conn);
	k_sem_take(&adv_sem, K_FOREVER);
	my_start_discovery();
	
	LOG_INF("main connection established waiting for discovery process...\n");
	k_sem_take(&adv_sem, K_FOREVER);
	/*MY_MAN_BUF*/
	LOG_DBG("subscribing to attributes");
	err = my_adv_subscribe_to_all();

	LOG_INF("attempting to start mitm module and advertisment\n");
	err = my_mitm_start_ad();

	if (err)
	{
		LOG_ERR("failing to activate mitm module (err %d)\n", err);
		return;
	}
	k_sem_take(&target_sem, K_FOREVER);
	LOG_INF("mitm module started \n");
	LOG_INF("starting uart_module");
	err = my_uart_init();
	LOG_INF("uart_module started waiting for input");
	char tx_buf[UART_MSG_SIZE];
	bool loop = true;
	while (k_msgq_get(&uart_msgq, &tx_buf, K_FOREVER) == 0 && loop)
	{
		print_uart(tx_buf);
		print_uart("\r\n");
		enum command cmd = handle_command(tx_buf);
		LOG_DBG("cmd = %u", cmd);

		switch(cmd){
			case ERROR:
				print_uart("unknown command \r\n");
				break;
			
			case EXIT:
				print_uart("exiting \r\n");
				loop = false;
				break;

			case LIST_CONNECTIONS:
				list_connections();
				break;
			case LIST_HANDLES:
				list_handles();
				break;
			default:
				print_uart("command executed \r\n");
				break;
		}

		
	}

	LOG_INF("Exiting %s thread.\n", __func__);
}
