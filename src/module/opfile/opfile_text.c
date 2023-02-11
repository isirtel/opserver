#include <stdio.h>
#include <errno.h>

#include "opfile_text.h"
#include "base/oplog.h"
#include "base/opmem.h"

struct file_to_text  *pdf_to_text(char *file_buf, unsigned int file_size)
{
	struct file_to_text *text = NULL;
	
	text = op_calloc(1, sizeof(struct file_to_text));
	if (!text) {
		log_warn_ex("op calloc failed, errno=%d\n", errno);
		goto out;
	}

out:
	return text;
}

