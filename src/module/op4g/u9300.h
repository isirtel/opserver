#ifndef _U_9300_H__
#define _U_9300_H__

#include "op4g_handle.h"

int u9300_init(int fd, char*center_message, struct _4g_module_init *);

void u9300_exit(void);

int u9300_uart_handle(int fd, unsigned int event_type, struct _4g_uart_handle *handle);
int u9300_interface(int fd, unsigned int event_type, struct _4g_iface_handle *iface);

#endif
