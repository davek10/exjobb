#ifndef MY_UART
#define MY_UART

extern struct k_msgq uart_msgq;
#define UART_MSG_SIZE 32
#define MY_SEND
#define MY_RECEIVE

int my_uart_init();
void print_uart(char *buf);

#endif