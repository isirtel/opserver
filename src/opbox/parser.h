#include <string.h>
#include <stdio.h>
#include <sys/types.h>

enum {
	PARSE_COLLAPSE  = 0x00010000, // treat consecutive delimiters as one
	PARSE_TRIM      = 0x00020000, // trim leading and trailing delimiters
// TODO: COLLAPSE and TRIM seem to always go in pair
	PARSE_GREEDY    = 0x00040000, // last token takes entire remainder of the line
	PARSE_MIN_DIE   = 0x00100000, // die if < min tokens found
	// keep a copy of current line
	PARSE_KEEP_COPY = 0x00200000,
	PARSE_EOL_COMMENTS = 0x00400000, // comments are recognized even if they aren't the first char
	PARSE_ALT_COMMENTS = 0x00800000, // delim[0] and delim[1] are two different allowed comment chars
	// (so far, delim[0] will only work as comment char for full-line comment)
	// (IOW: it works as if PARSE_EOL_COMMENTS is not set. sysctl applet is okay with this)
	PARSE_WS_COMMENTS  = 0x01000000, // comments are recognized even if there is whitespace before
	// ("line start><space><tab><space>#comment" is also comment, not only "line start>#comment")
	// NORMAL is:
	// * remove leading and trailing delimiters and collapse
	//   multiple delimiters into one
	// * warn and continue if less than mintokens delimiters found
	// * grab everything into last token
	// * comments are recognized even if they aren't the first char
	PARSE_NORMAL    = PARSE_COLLAPSE | PARSE_TRIM | PARSE_GREEDY | PARSE_EOL_COMMENTS,
};

char* skip_non_whitespace(const char *s);

char* skip_whitespace(const char *s);


typedef struct parser_t {
	FILE *fp;
	char *data;
	char *line, *nline;
	size_t line_alloc, nline_alloc;
	int lineno;
} parser_t;

parser_t* config_open(const char *filename);
/* delims[0] is a comment char (use '\0' to disable), the rest are token delimiters */
int config_read_ex(parser_t *parser, char **tokens, unsigned flags, const char *delims);
#define config_read(parser, tokens, max, min, str, flags) \
	config_read_ex(parser, tokens, ((flags) | (((min) & 0xFF) << 8) | ((max) & 0xFF)), str)
void config_close(parser_t *parser);


