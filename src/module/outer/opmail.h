#ifndef __OPMAIL_H__
#define __OPMAIL_H__
void *opmail_init(void);
void opmail_exit(void *mail);

void opmail_send_message(char *to, char *theme, char *content);
void opmail_send_message_ex(char *to, char *theme, const char *fmt, ...);


#endif
