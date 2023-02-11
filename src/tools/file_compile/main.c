#include <stdio.h>
#include<getopt.h>
#include <unistd.h>

#include "file_compile.h"
#include "base/oplog.h"

static char *file_compile_string = "h";

static struct option file_compile_long_options[] =
{
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};

int file_compile_help(char *prog)
{
	printf ("usage:\n");
	printf("%s <magic dir> <magic file output>\n", prog);
	return 0;
}

int main(int argc, char *argv[])
{
	int long_index = 0;
	int c = 0;

	while((c = getopt_long(argc, argv, file_compile_string, file_compile_long_options, &long_index)) > 0) {
		switch(c) {
			case 'h':
				return file_compile_help(argv[0]);
			default:
			break;
		}
	}

	if (argc != 3)
		return file_compile_help(argv[0]);

	if (access(argv[1], F_OK) < 0) {
		printf("dir <%s> is not exist\n", argv[1]);
		return 0;
	}

	return 0;
}
