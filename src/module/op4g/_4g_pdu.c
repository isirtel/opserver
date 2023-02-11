#include <stdio.h>
#include <string.h>

#include "_4g_pdu.h"
#include "op4g_handle.h"
#include "opbox/utils.h"


static int message_center_phone_change(char *center_num, char *dest, int dest_size)
{
	unsigned char i = 0;
	unsigned char len = 0;
	unsigned char buf[64] = {};
	unsigned char phone_num_spilite = 0;

	if (!dest || !dest_size) {
		printf("%s %d param is not support\n", __FUNCTION__, __LINE__);
		goto out;
	}

	if (!center_num) {
		printf("%s %d message center change failed\n", __FUNCTION__, __LINE__);
		goto out;
	}

	len = strlen(center_num);
	if (len < 3) {
		printf("%s %d phone num too short\n", __FUNCTION__, __LINE__);
		goto out;
	}

	if (center_num[0] != '+' && center_num[1] != '8' && center_num[2] != '6') {
		printf("%s %d not support[%s]\n", __FUNCTION__, __LINE__, center_num);
		goto out;
	}

	len = strlen(center_num+1) % 2;
	if (!len)
		snprintf((char*)buf, sizeof(buf), "91%s", center_num+1);
	else
		snprintf((char*)buf, sizeof(buf), "91%sF", center_num+1);

	len = strlen((char*)buf);
	phone_num_spilite = len/2;
	for (i = 2; i < len; i+=2) {
		buf[i]=buf[i]^buf[i+1];
		buf[i+1]=buf[i]^buf[i+1];
		buf[i]=buf[i]^buf[i+1];
	}

	return snprintf(dest, dest_size, "%02X%s", phone_num_spilite, buf);
out:
	return -1;
}

static int message_dest_phone_change(char *phone_num, char *dest,  int dest_size)
{
	unsigned char i = 0;
	unsigned char len = 0;
	unsigned char buf[64] = {};
	unsigned char buf_tmp[128] = {};

	if (!dest || !dest_size) {
		printf("%s %d param is not support\n", __FUNCTION__, __LINE__);
		goto out;
	}

	if (!phone_num) {
		printf("%s %d dest change failed\n", __FUNCTION__, __LINE__);
		goto out;
	}

	snprintf((char*)buf, sizeof(buf), "86%s", phone_num);

	len = strlen((char*)buf);
	if (!len)
		snprintf((char*)buf_tmp, sizeof(buf_tmp), "%s", buf);
	else
		snprintf((char*)buf_tmp, sizeof(buf_tmp), "%sF", buf);

	len = strlen((char*)buf_tmp);
	for (i = 0; i < len; i+=2) {
		buf_tmp[i]=buf_tmp[i]^buf_tmp[i+1];
		buf_tmp[i+1]=buf_tmp[i]^buf_tmp[i+1];
		buf_tmp[i]=buf_tmp[i]^buf_tmp[i+1];
	}

	return snprintf(dest, dest_size, "%s", buf_tmp);
out:
	return -1;
}

static int message_ucs2_change(char *message, char *dest, int dest_size)
{
	char buf[_4G_MESSAGE_SIZE];
	char buf_format[_4G_MESSAGE_SIZE+_4G_MESSAGE_SIZE];
	char buf_tmp[3] = {};
	unsigned char len = 0;
	int i = 0;
	size_t message_size = strlen(message);
	size_t mess_size = _4G_MESSAGE_SIZE;
	int ret = 0;
	
	if (!message || !dest || !dest_size) {
		printf("%s %d param is not support\n", __FUNCTION__, __LINE__);
		goto out;
	}

	memset(dest, 0, dest_size);
	if (utf8_to_unicode(message, &message_size, buf, &mess_size) < 0) {
		printf("%s %d utf8_to_unicode failed\n", __FUNCTION__, __LINE__);
		goto out;
	}

	len = (_4G_MESSAGE_SIZE-mess_size);
	
	snprintf(buf_tmp, sizeof(buf_tmp),"%02X",len);
	ret = 0;
	for (i = 0; i < len;i++)  {
		ret+=snprintf(buf_format+ret+2, _4G_MESSAGE_SIZE+_4G_MESSAGE_SIZE-ret-2, "%02X", (unsigned char)buf[i] );
	}

	buf_format[0] = buf_tmp[0];
	buf_format[1] = buf_tmp[1];
	return memlcpy(dest, dest_size, buf_format, ret+2);
out:
	return -1;
}

int message_ucs2_combi_mesage(char *center_num, char *phone_num, char *message, char*dest, int dest_size , int*count_set)
{
	char center_phone_buf[64];
	char phone_buf[64];
	char message_buf[_4G_MESSAGE_SIZE];
	int ret = 0;
	int ret1 = 0;
	int tmp_size = 0;
	int count = 0;

	ret = message_center_phone_change(center_num, center_phone_buf, sizeof(center_phone_buf));
	if (ret < 0)
		goto out;

	tmp_size = memlcpy(dest, dest_size, center_phone_buf, ret);
	
	ret = message_dest_phone_change(phone_num, phone_buf, sizeof(phone_buf));
	ret1 = ret;
	ret = snprintf(dest+tmp_size, dest_size-tmp_size, "1100%02X91", (unsigned int)ret);
	tmp_size+=ret;
	count = ret;
	tmp_size += memlcpy(dest+tmp_size, dest_size-tmp_size, phone_buf, ret1);
	count+=ret1;
	
	ret = snprintf(dest+tmp_size, dest_size-tmp_size, "%s", "000800");
	count+=ret;
	
	tmp_size+=ret;
	ret = message_ucs2_change(message, message_buf, sizeof(message_buf));

	count+=ret;
	
	tmp_size += memlcpy(dest+tmp_size, dest_size-tmp_size, message_buf, ret);
	dest[tmp_size]= 0x1a;
	*count_set = count/2;
	return tmp_size+1;
out:
	return -1;
}


