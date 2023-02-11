#ifndef __OPFILE_PUB_H__
#define __OPFILE_PUB_H__

enum {
	FILE_TYPE_unknow = 0,
	FILE_TYPE_rar,		
	FILE_TYPE_pdf,
	FILE_TYPE_zip,
	FILE_TYPE_elf,
	FILE_TYPE_jpeg,
	FILE_TYPE_jpg,
	FILE_TYPE_lua,
	FILE_TYPE_mk,
	FILE_TYPE_db,
	FILE_TYPE_docx,
	FILE_TYPE_xlsx,
	FILE_TYPE_pptx,
	FILE_TYPE_visio,
	FILE_TYPE_max,
};

struct file_ext_info {
	unsigned int file_type;
	char ext[64];
	char desc[256];
};

struct file_to_text {
	unsigned char *text;
	unsigned int size;
	unsigned int flag_encrypt:1;
};

#endif
