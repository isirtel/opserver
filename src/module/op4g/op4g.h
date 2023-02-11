#ifndef __OP4G_H__
#define __OP4G_H__

#undef _4G_TEST
void *op4g_init(void);

void op4g_exit(void *_4g);

void op4g_send_message(char *phone_num, char *message);
void op4g_send_message_ex(char *phone_num, const char *fmt, ...);


#endif

