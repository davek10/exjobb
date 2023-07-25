#ifndef MY_OBSERVER
#define MY_OBSERVER

#include <zephyr/sys/printk.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/hci.h>
#include <string.h>
#include <zephyr/bluetooth/addr.h>
#include "mitm.h"

int observer_start(void);
int set_target(const char*);
#endif /*MY_OBSERVER*/