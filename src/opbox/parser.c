#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdint.h>

#include "parser.h"

FILE* fopen_or_warn_stdin(const char *filename)
{
	FILE *fp = stdin;

	fp = fopen(filename, "r");
	
	return fp;
}

parser_t* config_open2(const char *filename)
{
	FILE* fp;
	parser_t *parser;

	fp = fopen_or_warn_stdin(filename);
	if (!fp)
		return NULL;
	parser = calloc(1, sizeof(*parser));
	parser->fp = fp;
	return parser;
}

parser_t* config_open(const char *filename)
{
	return config_open2(filename);
}

void config_close(parser_t *parser)
{
	if (parser) {
		if (PARSE_KEEP_COPY) /* compile-time constant */
			free(parser->data);
		fclose(parser->fp);
		free(parser->line);
		free(parser->nline);
		free(parser);
	}
}

static int get_line_with_continuation(parser_t *parser)
{
	size_t len, nlen;
	char *line;

	len = getline(&parser->line, &parser->line_alloc, parser->fp);
	if (len <= 0)
		return len;

	line = parser->line;
	for (;;) {
		parser->lineno++;
		if (line[len - 1] == '\n')
			len--;
		if (len == 0 || line[len - 1] != '\\')
			break;
		len--;

		nlen = getline(&parser->nline, &parser->nline_alloc, parser->fp);
		if (nlen <= 0)
			break;

		if (parser->line_alloc < len + nlen + 1) {
			parser->line_alloc = len + nlen + 1;
			line = parser->line = realloc(line, parser->line_alloc);
		}
		memcpy(&line[len], parser->nline, nlen);
		len += nlen;
	}

	line[len] = '\0';
	return len;
}


/*
0. If parser is NULL return 0.
1. Read a line from config file. If nothing to read then return 0.
   Handle continuation character. Advance lineno for each physical line.
   Discard everything past comment character.
2. if PARSE_TRIM is set (default), remove leading and trailing delimiters.
3. If resulting line is empty goto 1.
4. Look for first delimiter. If !PARSE_COLLAPSE or !PARSE_TRIM is set then
   remember the token as empty.
5. Else (default) if number of seen tokens is equal to max number of tokens
   (token is the last one) and PARSE_GREEDY is set then the remainder
   of the line is the last token.
   Else (token is not last or PARSE_GREEDY is not set) just replace
   first delimiter with '\0' thus delimiting the token.
6. Advance line pointer past the end of token. If number of seen tokens
   is less than required number of tokens then goto 4.
7. Check the number of seen tokens is not less the min number of tokens.
   Complain or die otherwise depending on PARSE_MIN_DIE.
8. Return the number of seen tokens.

mintokens > 0 make config_read() print error message if less than mintokens
(but more than 0) are found. Empty lines are always skipped (not warned about).
*/

char* skip_non_whitespace(const char *s)
{
	while (*s != '\0' && *s != ' ' && (unsigned char)(*s - 9) > (13 - 9))
		s++;

	return (char *) s;
}

char* skip_whitespace(const char *s)
{
	/* In POSIX/C locale (the only locale we care about: do we REALLY want
	 * to allow Unicode whitespace in, say, .conf files? nuts!)
	 * isspace is only these chars: "\t\n\v\f\r" and space.
	 * "\t\n\v\f\r" happen to have ASCII codes 9,10,11,12,13.
	 * Use that.
	 */
	while (*s == ' ' || (unsigned char)(*s - 9) <= (13 - 9))
		s++;

	return (char *) s;
}

int config_read_ex(parser_t *parser, char **tokens, unsigned flags, const char *delims)
{
	char *line, *p;
	int ntokens, mintokens;
	int t;
	char alt_comment_ch;

	if (!parser)
		return 0;

	alt_comment_ch = '\0';
	if (flags & PARSE_ALT_COMMENTS)
		alt_comment_ch = *delims++;

	ntokens = (uint8_t)flags;
	mintokens = (uint8_t)(flags >> 8);

again:
	memset(tokens, 0, sizeof(tokens[0]) * ntokens);

	/* Read one line (handling continuations with backslash) */
	if (get_line_with_continuation(parser) < 0)
		return 0;

	line = parser->line;

	/* Skip token in the start of line? */
	if (flags & PARSE_TRIM)
		line += strspn(line, delims + 1);

	p = line;
	if (flags & PARSE_WS_COMMENTS)
		p = skip_whitespace(p);
	if (p[0] == '\0' || p[0] == delims[0] || p[0] == alt_comment_ch)
		goto again;

	if (flags & PARSE_KEEP_COPY) {
		free(parser->data);
		parser->data = strdup(line);
	}

	/* Tokenize the line */
	t = 0;
	do {
		/* Pin token */
		tokens[t] = line;

		/* Combine remaining arguments? */
		if ((t != (ntokens-1)) || !(flags & PARSE_GREEDY)) {
			/* Vanilla token, find next delimiter */
			line += strcspn(line, (delims[0] && (flags & PARSE_EOL_COMMENTS)) ? delims : delims + 1);
		} else {
			/* Combining, find comment char if any */
			line = strchrnul(line, (flags & PARSE_EOL_COMMENTS) ? delims[0] : '\0');

			/* Trim any extra delimiters from the end */
			if (flags & PARSE_TRIM) {
				while (strchr(delims + 1, line[-1]) != NULL)
					line--;
			}
		}

		/* Token not terminated? */
		if ((flags & PARSE_EOL_COMMENTS) && *line == delims[0])
			*line = '\0'; /* ends with comment char: this line is done */
		else if (*line != '\0')
			*line++ = '\0'; /* token is done, continue parsing line */

		/* Skip possible delimiters */
		if (flags & PARSE_COLLAPSE)
			line += strspn(line, delims + 1);

		t++;
	} while (*line && *line != delims[0] && t < ntokens);

	if (t < mintokens) {
		if (flags & PARSE_MIN_DIE)
			printf("%s %d die\n", __FUNCTION__, __LINE__);
		goto again;
	}

	return t;
}
