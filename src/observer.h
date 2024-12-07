#ifndef MY_OBSERVER
#define MY_OBSERVER

int observer_start(void);
int set_target(const char*);
void my_clear_block();
int my_obs_print_blocklist();

#define MY_OBS_BLOCKLIST_CNT 32
#define MY_OBS_BLOCK_STR_LEN 256
#endif /*MY_OBSERVER*/