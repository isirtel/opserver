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

#include <sys/mman.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include "utils.h"
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include "hash.h"
#include <dirent.h>
#include <fcntl.h>
#include <execinfo.h>
#include <termios.h>
#include <errno.h>
#include <iconv.h>

#define BACKTRACE_SIZE   20

int isipv4(const char *ip)
{
	int dots = 0;
	int setions = 0;

	if (NULL == ip || *ip == '.') {
		return -1;
	}

	while (*ip) {
		
		if (*ip == '.') {
			dots ++;
			if (setions >= 0 && setions <= 255) {
				setions = 0;
				ip++;
				continue;
			}
			return -1;
		}else if (*ip >= '0' && *ip <= '9') {
			setions = setions * 10 + (*ip - '0');
		} else {
			return -1;
		}
		
		ip++;
	}

	if (setions >= 0 && setions <= 255) {
		if (dots == 3) {
			return 0;
		}
	}

	return -1;
}


int isport(const char *port)
{

	int i = 0;
	int len = 0;
	int port_num = -1;

	
	if (port == NULL) {
		return 0;
	}

	len = strlen(port);
	
	if (port[0] != '+' && (port[0] < '0' || port[0] > '9')) {
		return 0;
	}
	for (i = 1; i < len; i++) {
		if (port[i] < 0 || port[i] > '9') {
			return 0;
		}
	}

	port_num = atoi(port);

	if (port_num <=0 || port_num >65535) {
		return 0;
	}
	
	return 1;
}


void op_daemon(void) 
{ 
	int pid = 0; 
	int fd = 0;
	
	pid = fork();
	if(pid > 0) {
		exit(0);
	}
	else if(pid < 0) { 
		return;
	}
 
	setsid();
 
	pid = fork();
	
	if( pid > 0) {
		exit(0);
	}
	
	else if( pid< 0) {
		return;
	}

	fd = open ("/dev/null", O_RDWR);
	if (fd < 0) {
		return;
	}
	
	dup2 (fd, 0);
	dup2 (fd, 1);
	dup2 (fd, 2);
	
	
	return;
}



unsigned int ipv4touint(const char *str_ip)
{
	struct in_addr addr;
	unsigned int int_ip = 0;
	
	if(inet_aton(str_ip,&addr)) {
		int_ip = ntohl(addr.s_addr);
	}
	
	return int_ip;
}

char * uinttoipv4(unsigned int ip)
{

	struct in_addr addr;

	static char paddr[64] = {};
	memset(paddr, 0, sizeof(paddr));

	addr.s_addr = htonl(ip); 

	snprintf(paddr, sizeof(paddr), "%s", inet_ntoa(addr));

	return paddr;
}


int op_strlcpy(char *dest, const char *src, unsigned int dest_size)
{

	unsigned int size_copy = 0;

	if (!src || !dest || !dest_size)
		return 0;

	size_copy = dest_size > strlen(src)?strlen(src):dest_size-1;
	memcpy(dest, src, size_copy);
	dest[size_copy] = 0;

	return size_copy;
}

int memlcpy(void *dest, unsigned int dest_size, void *src, unsigned int src_size)
{
	unsigned int size_copy = 0;

	if (!src || !dest || !dest_size)
		return 0;

	memset(dest, 0, dest_size);
	size_copy = dest_size > src_size?src_size:dest_size;
	memcpy(dest, src, size_copy);
	return size_copy;
}

int is_dir_exist(char *dir, int create)
{
	DIR *_dir = NULL;
	if (!(_dir = opendir(dir))) {
		if (create) {
			if (mkdir(dir, 0755) < 0) {
				return 0;
			}else 
				return 1;
		} else
			return 0;
	}

	closedir(_dir);
	return 1;
}


static void dump_trace(int signo)
{
	(void)signo;
	int j, nptrs;
	void *buffer[BACKTRACE_SIZE];
	char **strings;
	
	nptrs = backtrace(buffer, BACKTRACE_SIZE);
	
	printf("------------------------SEGV!!!------------------------------\n");
 
	strings = backtrace_symbols(buffer, nptrs);
	if (strings == NULL) {
		perror("backtrace_symbols");
		return;
	}

	for (j = 0; j < nptrs; j++)
		printf("[%02d] %s\n", j, strings[j]);

	free(strings);
	printf("------------------------END------------------------------\n");
	return;

}

void signal_segvdump(void)
{
	signal(SIGSEGV, dump_trace);
	return;
}
void signal_ignore(int sig)
{
	signal(sig, SIG_IGN);
	return;

}

void print_hex(unsigned char *dest, int size)
{
	int i = 0;

	if (!dest || size <= 0)
		return;

	while(i < size)
		printf ("%02x", dest[i++]);

	printf("\n");

	return;
}

void print_HEX(unsigned char *dest, int size)
{
	int i = 0;

	if (!dest || size <= 0)
		return;

	while(i < size)
		printf ("%02X", dest[i++]);

	printf("\n");

	return;
}

void print_dec(unsigned char *dest, int size)
{
	int i = 0;

	if (!dest || size <= 0)
		return;

	while(i < size)
		printf ("%02d ", dest[i++]);

	printf("\n");

	return;
}

int uart_open(char *dev)
{
	struct termios term;
	int fd = -1;
	if (!dev) {
		printf ("%s %d dev name is unvalid\n", __FUNCTION__, __LINE__);
		goto out;
	}

	fd = open(dev, O_RDWR | O_NOCTTY | O_NONBLOCK);
	if (fd < 0) {
		//printf ("%s %d open failed[%s] [%d]\n", __FUNCTION__, __LINE__,dev, errno);
		goto out;
	}
	
	fcntl(fd, F_SETFL, O_RDWR);
	tcgetattr(fd, &term);
	term.c_lflag &= ~(ICANON | ECHO | ECHONL);
	term.c_lflag &= ~ISIG;
	term.c_lflag &= ~(IXON | ICRNL);
	term.c_oflag &= ~(ONLCR);
	term.c_iflag &= ~(IXOFF|IXON|IXANY|BRKINT|INLCR|ICRNL|IUCLC|IMAXBEL);
	cfsetspeed(&term, B9600);
	cfsetospeed(&term, B9600);
	
	term.c_cflag &= ~PARENB;
	term.c_cflag &= ~CSTOPB;
	term.c_cflag &= ~CSIZE;
	term.c_cflag |= CS8;

	term.c_cc[VMIN] = 1;
	term.c_cc[VTIME] = 0;
	tcsetattr(fd, TCSAFLUSH, &term);
	tcflush(fd,TCIOFLUSH);
out:
	return fd;
}

int unicode_to_utf8 (char *inbuf, size_t *inlen, char *outbuf, size_t *outlen)
{
	char *encTo = "UTF-8";
	char *encFrom = "UCS-2BE";

	char *tmpin = NULL;
	char *tmpout = NULL;
	int ret;

	iconv_t cd = iconv_open (encTo, encFrom);
	if (cd == (iconv_t)-1) {
		perror ("iconv_open");
	}

	tmpin = inbuf;
	tmpout = outbuf;

	ret = iconv (cd, &tmpin, inlen, &tmpout, outlen);
	if (ret == -1) {
		perror ("iconv");
	}

	iconv_close (cd);

	return ret;
}

int utf8_to_unicode (char *inbuf, size_t *inlen, char *outbuf, size_t *outlen)
{

	char *encTo = "UCS-2BE";
	char *encFrom = "UTF-8";
	char *tmpin = NULL;
	char *tmpout = NULL;
	int ret;

	iconv_t cd = iconv_open (encTo, encFrom);
	if (cd == (iconv_t)-1) {
		perror ("iconv_open");
		return  -1;
	}

	tmpin = inbuf;
	tmpout = outbuf;

	ret = iconv (cd, &tmpin, inlen, &tmpout, outlen);
	if (ret == -1) {
		perror ("iconv");
		return -1;
	}

	iconv_close (cd);

	return 0;
}

int is_leap_year(int year)
{

	if(year%400==0)
		return 1;
	else {
		if(year%4==0&&year%100!=0)
			return 1;
		else
			return 0;
	}

	return 0;
}


