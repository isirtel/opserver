/*
 * utils - misc libubox utility functions
 *
 * Copyright (C) 2012 Felix Fietkau <nbd@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __LIBUBOX_UTILS_H
#define __LIBUBOX_UTILS_H

#include <sys/types.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>

#define ARRAY_SIZE(X) (sizeof(X)/sizeof(X[0]))
int isipv4(const char *ip);

int isport(const char *port);

void op_daemon(void);

unsigned int ipv4touint(const char *str_ip);

char * uinttoipv4(unsigned int ip);

int op_strlcpy(char *dest, const char *src, unsigned int dest_size);

int memlcpy(void *dest, unsigned int dest_size, void *src, unsigned int src_size);

int is_dir_exist(char *dir, int create);

void signal_segvdump(void);
void signal_ignore(int sig);

void print_hex(unsigned char *dest, int size);
void print_dec(unsigned char *dest, int size);

void print_HEX(unsigned char *dest, int size);

int uart_open(char *dev);
int utf8_to_unicode (char *inbuf, size_t *inlen, char *outbuf, size_t *outlen);

int unicode_to_utf8 (char *inbuf, size_t *inlen, char *outbuf, size_t *outlen);

int is_leap_year(int year);

#endif
