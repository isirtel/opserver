#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "opfile.h"
#include "base/oplog.h"
#include "base/opmem.h"
#include "libxml/tree.h"
#include "config.h"
#include "iniparser.h"
#include "opbox/utils.h"
#include "opbox/hash.h"
#include "hs/hs.h"
#include "opfile_text.h"

#define OPFILE_MAX_CHECK_SIZE 8192 /*8k*/
#define OPFILE_MAGIC_PATH "opfile:magic_path"
#define OPFILE_MAX_HS_SCAN 20

#define OPFILE_SUPPORT_MAX_EXPRESS_SIZE 10000

#define OPFILE_EXPRESS_SIZE 256

struct hs_pack_struct {
	char **express ;
	unsigned int *express_id ;
	unsigned int *flag;
	unsigned int num;
	unsigned int index;
};

struct file_magic {
	char ext[64];
	char express[OPFILE_EXPRESS_SIZE];
	char desc[256];
	/*express pack*/
	unsigned int express_id;
	unsigned file_type;
};

struct file_magic_ex {

	struct file_magic *magic[OPFILE_MAX_HS_SCAN];
	unsigned int matched_num;
};

struct hs_magic {
    hs_database_t *db;
    hs_scratch_t *scratch;
};

struct opfile_info {
	void *magic_hash;
	struct hs_magic hs;
};

struct file_type_map {
	unsigned int file_type;
	char *ext;
};

typedef struct file_to_text  *(*opfile_text_cb)(char *, unsigned int );

struct file_text_map {
	unsigned int file_type;
	opfile_text_cb text_cb;
};

static struct file_type_map magic_file_type[FILE_TYPE_max] = {
	[FILE_TYPE_pdf] = {.file_type = FILE_TYPE_pdf, .ext="pdf"},
	[FILE_TYPE_zip] = {.file_type = FILE_TYPE_zip, .ext="zip"},
	[FILE_TYPE_rar] = {.file_type = FILE_TYPE_zip, .ext="rar"},
	[FILE_TYPE_elf] = {.file_type = FILE_TYPE_zip, .ext="elf"},
	[FILE_TYPE_jpeg] = {.file_type = FILE_TYPE_zip, .ext="jpeg"},
	[FILE_TYPE_jpg] = {.file_type = FILE_TYPE_zip, .ext="jpg"},
	[FILE_TYPE_lua] = {.file_type = FILE_TYPE_zip, .ext="lua"},
	[FILE_TYPE_mk] = {.file_type = FILE_TYPE_zip, .ext="mk"},
	[FILE_TYPE_db] = {.file_type = FILE_TYPE_zip, .ext="db"},
	[FILE_TYPE_docx] = {.file_type = FILE_TYPE_zip, .ext="docx"},
	[FILE_TYPE_xlsx] = {.file_type = FILE_TYPE_zip, .ext="xlsx"},
	[FILE_TYPE_pptx] = {.file_type = FILE_TYPE_zip, .ext="pptx"},
	[FILE_TYPE_visio] = {.file_type = FILE_TYPE_zip, .ext="vd"},
};

static struct file_text_map magic_file_text[FILE_TYPE_max] = {
	[FILE_TYPE_pdf] = {.file_type = FILE_TYPE_pdf, .text_cb= pdf_to_text},
};


static struct opfile_info *self = NULL;

static void file_magic_review (void *node) 
{
	struct file_magic *magic = (struct file_magic *)node;
	if (!magic)
		return;

	log_debug_ex("magic:ext[%s], express[%s], desc[%s], express_id:%u, file_type=%u\n", magic->ext, magic->express, magic->desc?magic->desc:"null", magic->express_id, magic->file_type);

	return;
}

static void hs_magic_pack (void *node, void*arg)
{
	struct file_magic *magic = (struct file_magic *)node;
	struct hs_pack_struct *hs_pack = (struct hs_pack_struct *)arg;
	if (!magic || !hs_pack)
		return;

	if (hs_pack->index >= hs_pack->num) {
		log_warn_ex("hs pack index to long\n");
		return;
	}

	hs_pack->express[hs_pack->index] = magic->express;
	hs_pack->express_id[hs_pack->index] = magic->express_id;
	hs_pack->flag[hs_pack->index] = HS_FLAG_DOTALL;
	hs_pack->index++;
	return;
}

static int opfile_hs_compile(struct opfile_info *opfile)
{
	unsigned int hash_num = 0;
	hs_error_t err = 0;
	char **express = NULL;
	unsigned int *express_id = NULL;
	unsigned int *flag = 0;
	hs_compile_error_t *compile_err;
	struct hs_pack_struct hs_pack;

	if ((hash_num = op_hash_num_items(opfile->magic_hash)) > OPFILE_SUPPORT_MAX_EXPRESS_SIZE) {
		log_warn_ex("too much express, support num:%u\n", OPFILE_SUPPORT_MAX_EXPRESS_SIZE);
		goto failed;
	}

	express = (char **)op_calloc(1, hash_num * sizeof(char*));
	if (!express) {
		log_warn_ex("op calloc failed\n");
		goto failed;
	}

	express_id = op_calloc(1, hash_num * sizeof(unsigned int));
	if (!express_id) {
		log_warn_ex("op calloc failed\n");
		goto failed;
	}

	flag = op_calloc(1, hash_num * sizeof(unsigned int));
	if (!flag) {
		log_warn_ex("op calloc failed\n");
		goto failed;
	}

	memset(&hs_pack, 0, sizeof(hs_pack));
	hs_pack.express = express;
	hs_pack.express_id = express_id;
	hs_pack.flag = flag;
	hs_pack.num = hash_num;
	hs_pack.index = 0;

	
	log_debug_ex("magic num:%u\n", hash_num);
	op_hash_doall_arg(opfile->magic_hash, hs_magic_pack, &hs_pack);

	err = hs_compile_multi((const char * const*)express,flag, express_id, hash_num, HS_MODE_BLOCK, NULL, &opfile->hs.db, &compile_err);
	if (err != HS_SUCCESS) {
        log_warn_ex("hs_compile_multi failed: %s\n", compile_err->message);
		goto failed;
	}
	
    if (hs_alloc_scratch(opfile->hs.db, &opfile->hs.scratch) != HS_SUCCESS) {
        log_warn_ex("hs_alloc_scratch failed\n");
		goto failed;
    }
	
	op_free(express);
	op_free(express_id);

	return 0;

failed:
	if (express)
		op_free(express);
	if (express_id)
		op_free(express_id);
	return -1;
}

static int opfile_parse_magic(char *magic_path)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr root = NULL;
	xmlNodePtr node_magic = NULL;
	xmlNodePtr magic_child = NULL;
	xmlChar *ext = NULL;
	xmlChar *express = NULL;
	xmlChar *desc = NULL;
	unsigned int express_id = 100;
	struct opfile_info *opfile = self;
	struct file_magic *magic = NULL;
	
	struct file_magic *magic_find = NULL;
	unsigned int i = 0;
	unsigned int len = 0;
	
    doc = xmlReadFile(magic_path,"UTF-8",XML_PARSE_RECOVER);
	if (!doc) {
		log_warn_ex("xml read %s failed\n", magic_path);
		goto failed;
	}
	
	root=xmlDocGetRootElement(doc);
	if (!root) {
		log_warn_ex("get root element failed\n");
		goto failed;
	}

	node_magic = root->children;

	for (node_magic = root->children; node_magic; node_magic = node_magic->next) {
		if (node_magic->type != XML_ELEMENT_NODE || xmlStrcasecmp(node_magic->name, BAD_CAST"magic"))
			continue;
		
		ext = xmlGetProp(node_magic, BAD_CAST"ext");
		if (!ext) {
			log_warn_ex("magic, can not find attr ext\n");
			goto failed;
		}

		for(magic_child = node_magic->children; magic_child; magic_child = magic_child->next) {
			if (magic_child->type != XML_ELEMENT_NODE || xmlStrcasecmp(magic_child->name, BAD_CAST"express"))
				continue;

			magic = op_calloc(1, sizeof(*magic));
			if (!magic) {
				log_warn_ex("op calloc failed\n");
				goto failed;
			}

			op_strlcpy(magic->ext, (char*)ext, sizeof(magic->ext));

			express = xmlNodeGetContent(magic_child);
			if (!express) {
				log_warn_ex("magic, express is unvalid\n");
				goto failed;
			}
			op_strlcpy(magic->express, (char*)express, sizeof(magic->express));
			xmlFree(express);
			express = NULL;

			desc = xmlGetProp(magic_child, BAD_CAST"desc");
			if (desc) {
				op_strlcpy(magic->desc, (char*)desc, sizeof(magic->desc));
				xmlFree(desc);
				desc = NULL;
			}

			magic->express_id = express_id++;
			len = sizeof(magic_file_type)/sizeof(magic_file_type[0]);

			for (i = 0; i < len; i++) {
				if (!magic_file_type[i].ext || !magic->ext)
					continue;
				
				if (strcmp(magic->ext, magic_file_type[i].ext))
					continue;

				magic->file_type = magic_file_type[i].file_type;
				break;
			}

			if (i >= len)
				magic->file_type = FILE_TYPE_unknow;

			log_debug_ex("magic express id:%u\n", magic->express_id);
			magic_find = op_hash_retrieve(opfile->magic_hash, magic);
			if (magic_find) {
				log_warn_ex("magic dup, src ext[%s], express[%s], desc[%s], express_id:%u\n", magic->ext, magic->express, magic->desc?magic->desc:"null",magic->express_id);
				
				log_warn_ex("magic dup, dest ext[%s], express[%s], desc[%s], express_id:%u\n", magic_find->ext, magic_find->express, magic_find->desc?magic_find->desc:"null", magic_find->express_id);
				op_free(magic);
				magic = NULL;
				goto failed;
			}
			
			op_hash_insert(opfile->magic_hash, magic);		
			magic = NULL;
		}

		xmlFree(ext);
		ext = NULL;
	}

	op_hash_doall(opfile->magic_hash, file_magic_review);

	return 0;

failed:
	if (doc) {
		xmlFreeDoc(doc);
		xmlCleanupParser();
	}

	if (magic)
		op_free(magic);

	if (ext)
		xmlFree(ext);

	if (desc)
		xmlFree(desc);

	if (express)
		xmlFree(express);	

	return -1;
}

static unsigned long file_magic_hash (const void *node)
{
	struct file_magic *magic = (struct file_magic*)node;
	if (!magic)
		return 0;

	return magic->express_id;
}

static int file_magic_compare (const void *node_src, const void *node_dest)
{
	struct file_magic *magic_src = (struct file_magic*)node_src;
	struct file_magic *magic_dest = (struct file_magic*)node_dest;
	if (!magic_src || !magic_dest)
		return 1;

	return !(magic_src->express_id == magic_dest->express_id);
}

void *opfile_init(void)
{
	struct opfile_info *opfile = NULL;
	const char *str = NULL;
	dictionary *dict = NULL;
	char magic_path[128] = {};
	opfile = op_calloc(1, sizeof(struct opfile_info));
	if (!opfile) {
		log_warn_ex("op calolc failed\n");
		goto out;
	}

	self = opfile;

	opfile->magic_hash = op_hash_new(file_magic_hash, file_magic_compare);
	if (!opfile->magic_hash) {
		log_warn_ex("op hash failed\n");
		goto out;
	}

	dict = iniparser_load(OPSERVER_CONF);
	if (!dict) {
		log_error_ex ("iniparser_load faild[%s]\n", OPSERVER_CONF);
		goto out;
	}

	if(!(str = iniparser_getstring(dict,OPFILE_MAGIC_PATH,NULL))) {
		log_warn_ex ("iniparser_getstring faild[%s]\n", OPFILE_MAGIC_PATH);
		goto out;
	}

	op_strlcpy(magic_path, str, sizeof(magic_path));
	iniparser_freedict(dict);
	dict = NULL;

	if (opfile_parse_magic(magic_path) < 0) {
		log_warn_ex("parge magic %s failed\n", magic_path);
		goto out;
	}

	/* hyperscan compile */
	if (opfile_hs_compile(opfile) < 0) {
		log_warn_ex("opfile_hs_compile failed\n");
		goto out;
	}

	//opfile_to_text_path("/home/isir/developer/dd.pdf", -1);

	return opfile;
out:
	if (dict)
		iniparser_freedict(dict);

	opfile_exit(opfile);
	return NULL;
}

void opfile_exit(void *file)
{
	if (!file)
		return;

	return;
}

static int opfile_magic_hs_process(unsigned int id,unsigned long long from,unsigned long long to,unsigned int flags,void *context)
{
	struct opfile_info *opfile = self;
	struct file_magic_ex *magic = (struct file_magic_ex *)context;
	struct file_magic *_magic = NULL;
	struct file_magic magic_compare;
	if (!opfile)
		return 0;
	
	magic_compare.express_id = id;
	_magic = op_hash_retrieve(opfile->magic_hash, &magic_compare);
	if (!_magic)
		log_warn_ex("we should find magic by id[%u],but we not find actually\n", id);

	if (magic->matched_num >= OPFILE_MAX_HS_SCAN)
		return HS_SCAN_TERMINATED;

	magic->magic[magic->matched_num++] =  _magic;

	/* matchd one time */
	return HS_SUCCESS;
}

struct file_ext_info * opfile_check_mem(char *file_buf, unsigned int size)
{
	struct opfile_info *opfile = self;
	struct file_ext_info *file = NULL;
	struct file_magic_ex *magic_ex = NULL;
	struct file_magic *magic = NULL;
	int ret = 0;
	unsigned int i = 0;
	unsigned int max_index = 0;
	char *max_express = NULL;
	unsigned int hs_check_size = 0;
	if (!opfile)
		return NULL;

	file = op_calloc(1, sizeof(*file));
	if (!file) {
		log_warn_ex("op calooc failed\n");
		goto failed;
	}

	magic_ex = op_calloc(1, sizeof(*magic_ex));
	if (!magic_ex) {
		log_warn_ex("op calooc failed\n");
		goto failed;
	}

	hs_check_size = size > OPFILE_MAX_CHECK_SIZE?OPFILE_MAX_CHECK_SIZE:size;
	ret = hs_scan(opfile->hs.db, file_buf, hs_check_size, 0, opfile->hs.scratch, opfile_magic_hs_process, magic_ex);
	if (ret != HS_SUCCESS && ret != HS_SCAN_TERMINATED)
		goto failed;
	
	if (!magic_ex->matched_num || !magic_ex->magic[0] || !magic_ex->magic[0]->express) /* not matchd*/ {
		/*try check by size*/
		goto failed;
	}

	max_index = 0;
	max_express = magic_ex->magic[0]->express;
	for (i = 1; i < magic_ex->matched_num; i++) {
		if (!magic_ex->magic[i] || !magic_ex->magic[i]->express)
			continue;

		if (strlen(magic_ex->magic[i]->express) > strlen(max_express)) {
			max_index = i;
			max_express = magic_ex->magic[i]->express;
		}
	}

	magic = magic_ex->magic[max_index];
	
	log_debug_ex("match[%u]:ext[%s], express[%s], desc[%s], express_id:%u, file_type=%u\n",
			magic_ex->matched_num,magic->ext, magic->express, magic->desc?magic->desc:"null", magic->express_id, magic->file_type);
	file->file_type = magic->file_type;
	op_strlcpy(file->ext, magic->ext, sizeof(file->ext));
	op_strlcpy(file->desc, magic->desc, sizeof(file->desc));
	op_free(magic_ex);
	return file;
failed:
	if (file)
		op_free(file);
	return NULL;
}

struct file_ext_info * opfile_check_path(char *file_path)
{
	char *buf = NULL;
	int fd = 0;
	int size = 0;
	struct file_ext_info *file = NULL;

	if (!file_path)
		return NULL;

	if (access(file_path, F_OK) < 0) {
		log_warn_ex("can not find %s\n", file_path);
		return NULL;
	}

	buf = op_calloc(1, OPFILE_MAX_CHECK_SIZE);
	if (!buf) {
		log_warn_ex("op calloc failed\n");
		return NULL;
	}

	fd = open(file_path, O_RDWR);
	if (fd < 0) {
		op_free(buf);
		log_warn_ex("open %s failed, errno=%d\n", file_path, errno);
		return NULL;
	}

	size = read(fd, buf, OPFILE_MAX_CHECK_SIZE);
	if (size <= 0) {
		log_warn_ex("read %s failed,ret=%d erno=%d\n", file_path, size,errno);
		op_free(buf);
		close(fd);
		return NULL;
	}

	close(fd);
	log_debug_ex("check %s magic\n", file_path);
	file = opfile_check_mem(buf, size);
	op_free(buf);
	return file;
}

struct file_to_text *opfile_to_text(char *file_buf, unsigned int size, unsigned int file_type)
{
	struct file_ext_info *info = NULL;
	unsigned int type = 0;
	if (file_type > FILE_TYPE_unknow && file_type < FILE_TYPE_max) {
		if (!magic_file_text[file_type].text_cb)
			return NULL;

		return magic_file_text[file_type].text_cb(file_buf, size);
	}

	info = opfile_check_mem(file_buf, size);
	if (!info || (info->file_type <= FILE_TYPE_unknow || info->file_type >= FILE_TYPE_max)) {
		if (info)
			op_free(info);

		goto out;
	}

	type = info->file_type;
	op_free(info);

	if (!magic_file_text[type].text_cb)
		goto out;
	
	return magic_file_text[type].text_cb(file_buf, size);

out:
	return NULL;
}

struct file_to_text *opfile_to_text_path(char *file_path, unsigned int file_type)
{
	struct stat st;
	char *file = NULL;
	int fd = 0;
	struct file_to_text * text = NULL;

	if (stat(file_path, &st)  < 0) {
		log_warn_ex("file %s not find\n", file_path);
		return NULL;
	}

	file = op_calloc(1, st.st_size);
	if (!file) {
		log_warn_ex("calloc failed, errno=%d\n", errno);
		return NULL;
	}

	fd = open(file_path, O_RDONLY);
	if (fd < 0) {
		log_warn_ex("open failed, errno=%d\n", errno);
		goto out;
	}

	read(fd, file, st.st_size);
	close(fd);
	
	text = opfile_to_text(file, st.st_size, file_type);
	op_free(file);
	return text;

out:
	if (file)
		op_free(file);
	return NULL;

}


