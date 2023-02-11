#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <arpa/telnet.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "vty.h"

static char telnet_backward_char = 0x08;
static char telnet_space_char = ' ';
static struct cmd_token token_cr;
static char *command_cr = NULL;
static vector cmdvec;

#define vector_slot(V,I)  ((V)->index[(I)])
#define vector_active(V) ((V)->active)
#define TERMINAL_RECORD(t) ((t) >= TERMINAL_OPTION)
#define DECIMAL_STRLEN_MAX 10
#define CONTROL(X)  ((X) - '@')
#define VTY_PRE_ESCAPE 1
#define VTY_ESCAPE     2
#define VTY_LITERAL    3
#define CMD_ARGC_MAX   25
#define VTY_NEWLINE  ((vty->type == VTY_TERM) ? "\r\n" : "\n")

#define CMD_SUCCESS              0
#define CMD_WARNING              1
#define CMD_ERR_NO_MATCH         2
#define CMD_ERR_AMBIGUOUS        3
#define CMD_ERR_INCOMPLETE       4
#define CMD_ERR_EXEED_ARGC_MAX   5
#define CMD_ERR_NOTHING_TODO     6
#define CMD_COMPLETE_FULL_MATCH  7
#define CMD_COMPLETE_MATCH       8
#define CMD_COMPLETE_LIST_MATCH  9
#define CMD_SUCCESS_DAEMON      10

#define VCTOR_CREATE_SIZE       10
#define VTY_OUT_SIZE            4096

#define MATCHER_ERROR(matcher_rv) \
	((matcher_rv) == MATCHER_INCOMPLETE \
	|| (matcher_rv) == MATCHER_NO_MATCH \
	|| (matcher_rv) == MATCHER_AMBIGUOUS \
	|| (matcher_rv) == MATCHER_EXCEED_ARGC_MAX \
	)

#define IPV6_ADDR_STR		"0123456789abcdefABCDEF:.%"
#define IPV6_PREFIX_STR		"0123456789abcdefABCDEF:.%/"
#define STATE_START		1
#define STATE_COLON		2
#define STATE_DOUBLE		3
#define STATE_ADDR		4
#define STATE_DOT               5
#define STATE_SLASH		6
#define STATE_MASK		7

enum cmd_token_type
{
	TOKEN_TERMINAL = 0,
	TOKEN_MULTIPLE,
	TOKEN_KEYWORD,
};

enum cmd_terminal_type
{
	_TERMINAL_BUG = 0,
	TERMINAL_LITERAL,
	TERMINAL_OPTION,
	TERMINAL_VARIABLE,
	TERMINAL_VARARG,
	TERMINAL_RANGE,
	TERMINAL_IPV4,
	TERMINAL_IPV4_PREFIX,
	TERMINAL_IPV6,
	TERMINAL_IPV6_PREFIX,
};

enum filter_type
{
	FILTER_RELAXED,
	FILTER_STRICT
};

enum matcher_rv
{
	MATCHER_OK,
	MATCHER_COMPLETE,
	MATCHER_INCOMPLETE,
	MATCHER_NO_MATCH,
	MATCHER_AMBIGUOUS,
	MATCHER_EXCEED_ARGC_MAX
};

enum match_type 
{
	no_match,
	extend_match,
	ipv4_prefix_match,
	ipv4_match,
	ipv6_prefix_match,
	ipv6_match,
	range_match,
	vararg_match,
	partly_match,
	exact_match 
};

struct cmd_matcher
{
	struct cmd_element *cmd;
	enum filter_type filter;
	vector vline;
	unsigned int index;
	enum match_type *_match_type;
	vector *match;
	unsigned int word_index;
};

struct format_parser_state
{
	vector topvect;
	vector intvect;
	vector curvect;
	const char *string;
	const char *cp;
	const char *dp;
	int in_keyword;
	int in_multiple;
	int just_read_word;
};

static int vector_empty_slot (vector v)
{
	unsigned int i;

	if (v->active == 0)
		return 0;

	for (i = 0; i < v->active; i++)
		if (v->index[i] == 0)
			return i;

	return i;
}

static int vector_ensure (vector v, unsigned int num)
{
	if (v->alloced > num)
		return 0;

	v->index = realloc ( v->index, sizeof (void *) * (v->alloced * 2));
	if (!v->index) {
		printf ("%s %d realloc failed\n", __FILE__, __LINE__);
		return -1;
	}

	memset (&v->index[v->alloced], 0, sizeof (void *) * v->alloced);
	v->alloced *= 2;

	if (v->alloced <= num)
		vector_ensure (v, num);

	return 0;
}


static int vector_set (vector v, void *val)
{
	unsigned int i;

	i = vector_empty_slot (v);
	if (vector_ensure (v, i) < 0)
		return -1;

	v->index[i] = val;

	if (v->active <= i)
		v->active = i + 1;

	return i;
}

static int vector_set_index (vector v, unsigned int i, void *val)
{
	if (vector_ensure (v, i) < 0)
		return -1;

	v->index[i] = val;

	if (v->active <= i)
		v->active = i + 1;

	return i;
}

static vector vector_init (void)
{
	vector v = NULL;
	v = calloc (1, sizeof (struct _vector));
	if (!v) {
		printf ("%s %d calloc failed[%d]\n",__FILE__,__LINE__, errno);
		return NULL;
	}
	
	v->alloced = VCTOR_CREATE_SIZE;
	v->active = 0;
	v->index = calloc (1, sizeof (void *) * v->alloced);
	if (!v->index) {
		printf ("%s %d calloc failed[%d]\n",__FILE__,__LINE__, errno);
		free(v);
		return NULL;
	}

	return v;
}

static void vty_out(struct _vty *vty, const char *fmt, ...)
{
	va_list args;
	size_t size = 0;
	char *cli_buf = NULL;

	if (!vty)
		goto out;

	cli_buf = calloc(1, VTY_OUT_SIZE);
	if (!cli_buf) {
		printf ("%s %d calloc failed[%d]\n",__FILE__,__LINE__, errno);
		goto out;
	}

	va_start(args, fmt);
	size = vsnprintf(cli_buf, VTY_OUT_SIZE, fmt, args);
	va_end(args);

	if (write(vty->fd, (unsigned char*)cli_buf, size) < 0) {
		printf ("%s %d write failed[%d]\n",__FILE__,__LINE__, errno);
		goto out;
	}
out:
	if (cli_buf)
		free(cli_buf);
	return;
}

static void vty_write(struct _vty *vty, char *buf, int size)
{
	if (write(vty->fd, buf, size) < 0)
		printf ("%s %d write failed[%d]\n",__FILE__,__LINE__, errno);

	return;
}

void vty_backward_char (struct _vty *vty)
{
	if (vty->cp > 0) {
		vty->cp--;
		vty_write (vty, &telnet_backward_char, 1);
	}

	return;
}

static void vty_kill_line (struct _vty *vty)
{
	int i;
	int size;

	size = vty->length - vty->cp;

	if (size == 0)
		return;

	for (i = 0; i < size; i++)
		vty_write (vty, &telnet_space_char, 1);

	for (i = 0; i < size; i++)
		vty_write (vty, &telnet_backward_char, 1);

	memset (&vty->buf[vty->cp], 0, size);
	vty->length = vty->cp;
	return;
}

static void vty_beginning_of_line (struct _vty *vty)
{
	while (vty->cp)
		vty_backward_char (vty);

	return;
}

static void vty_kill_line_from_beginning (struct _vty *vty)
{
	vty_beginning_of_line (vty);
	vty_kill_line (vty);
	return;
}


static void vty_redraw_line (struct _vty *vty)
{
	vty_write (vty, vty->buf, vty->length);
	vty->cp = vty->length;
	return;
}

static void vty_forward_char (struct _vty *vty)
{

	if (vty->cp < vty->length) {
		vty_write (vty, &vty->buf[vty->cp], 1);
		vty->cp++;
	}

	return;
}

const char * cmd_prompt (unsigned int node)
{
	struct cmd_node *cnode;
	cnode = vector_slot (cmdvec, node);
	return cnode->prompt;
}

static void vty_prompt (struct _vty *vty)
{
	vty_out (vty, cmd_prompt (vty->node), vty->hostname);
	return;
}

static void vty_down_level (struct _vty *vty)
{
	vty_out (vty, "%s", VTY_NEWLINE);
	vty_prompt (vty);
	vty->cp = 0;
	return;
}

static void vty_end_of_line (struct _vty *vty)
{
	while (vty->cp < vty->length)
		vty_forward_char (vty);

	return;
}
static void vty_backward_word (struct _vty *vty)
{
	while (vty->cp > 0 && vty->buf[vty->cp - 1] == ' ')
		vty_backward_char (vty);

	while (vty->cp > 0 && vty->buf[vty->cp - 1] != ' ')
		vty_backward_char (vty);

	return;
}

static void vty_delete_char (struct _vty *vty)
{
	int i;
	int size;

	if (vty->length == 0) {
		vty_down_level (vty);
		return;
	}

	if (vty->cp == vty->length)
		return;

	size = vty->length - vty->cp;

	vty->length--;
	memmove (&vty->buf[vty->cp], &vty->buf[vty->cp + 1], size - 1);
	vty->buf[vty->length] = '\0';

	vty_write (vty, &vty->buf[vty->cp], size - 1);
	vty_write (vty, &telnet_space_char, 1);

	for (i = 0; i < size; i++)
		vty_write (vty, &telnet_backward_char, 1);

	return;
}

/* Forward word. */
static void vty_forward_word (struct _vty *vty)
{
	while (vty->cp != vty->length && vty->buf[vty->cp] != ' ')
		vty_forward_char (vty);

	while (vty->cp != vty->length && vty->buf[vty->cp] == ' ')
		vty_forward_char (vty);

	return;
}

static void vty_forward_kill_word (struct _vty *vty)
{
	while (vty->cp != vty->length && vty->buf[vty->cp] == ' ')
		vty_delete_char (vty);
	while (vty->cp != vty->length && vty->buf[vty->cp] != ' ')
		vty_delete_char (vty);

	return;
}

static void vty_buf_put (struct _vty *vty, char c)
{
	vty->buf[vty->cp] = c;
	vty->buf[vty->max - 1] = '\0';
	return;
}

static void vty_self_insert (struct _vty *vty, char c)
{
	int i;
	int length;

	if (vty->length + 1 >= vty->max)
		return;

	length = vty->length - vty->cp;
	memmove (&vty->buf[vty->cp + 1], &vty->buf[vty->cp], length);
	vty->length++;
	vty->buf[vty->length] = '\0';

	vty_buf_put (vty, c);

	vty_write (vty, &vty->buf[vty->cp], length + 1);
	for (i = 0; i < length; i++)
		vty_write (vty, &telnet_backward_char, 1);

	vty->cp++;

	return;
}

static void vty_self_insert_overwrite (struct _vty *vty, char c)
{

	if (vty->cp == vty->length) {
		vty_self_insert (vty, c);
		return;
	}

	vty_buf_put (vty, c);
	vty->cp++;
	vty_write (vty, &c, 1);
	return;
}

static void vty_delete_backward_char (struct _vty *vty)
{
	if (vty->cp == 0)
		return;

	vty_backward_char (vty);
	vty_delete_char (vty);

	return;
}

static void vty_clear_buf (struct _vty *vty)
{
	memset (vty->buf, 0, vty->max);
	return;
}

static void format_parser_error(struct format_parser_state *state, const char *message)
{
	int offset = state->cp - state->string + 1;

	fprintf(stderr, "\nError parsing command: \"%s\"\n", state->string);
	fprintf(stderr, "                        %*c\n", offset, '^');
	fprintf(stderr, "%s at offset %d.\n", message, offset);
	fprintf(stderr, "This is a programming error. Check your DEFUNs etc.\n");
	return;
}

static int vty_telnet_option (struct _vty *vty, unsigned char *buf, int nbytes)
{

	switch (buf[0])
	{
		case SB:
			vty->sb_len = 0;
			vty->iac_sb_in_progress = 1;
			return 0;
		case SE: 
			{
				if (!vty->iac_sb_in_progress)
					return 0;

				if ((vty->sb_len == 0) || (vty->sb_buf[0] == '\0')) {
					vty->iac_sb_in_progress = 0;
					return 0;
				}

				switch (vty->sb_buf[0])
					{
						case TELOPT_NAWS:
							if (vty->sb_len == TELNET_NAWS_SB_LEN) {
								vty->width = ((vty->sb_buf[1] << 8)|vty->sb_buf[2]);
								vty->height = ((vty->sb_buf[3] << 8)|vty->sb_buf[4]);
							}
						break;
						default:
							break;
					}
				vty->iac_sb_in_progress = 0;
				return 0;
			}

		default:
			break;
	}
	
	return 1;
}

static int  cmd_try_do_shortcut (unsigned int node, char* first_word) {
	if ( first_word && !strcmp( "do", first_word ) )
		return 1;
	return 0;
}

static void vty_history_print (struct _vty *vty)
{
	int length;

	vty_kill_line_from_beginning (vty);

	length = strlen (vty->hist[vty->hp]);
	memcpy (vty->buf, vty->hist[vty->hp], length);
	vty->cp = vty->length = length;
	vty->buf[vty->length] = '\0';
	vty_redraw_line (vty);
	return;
}

static void vty_transpose_chars (struct _vty *vty)
{
	char c1, c2;

	if (vty->length < 2 || vty->cp < 1)
		return;

	if (vty->cp == vty->length) {
		c1 = vty->buf[vty->cp - 1];
		c2 = vty->buf[vty->cp - 2];

		vty_backward_char (vty);
		vty_backward_char (vty);
		vty_self_insert_overwrite (vty, c1);
		vty_self_insert_overwrite (vty, c2);
	} else {
		c1 = vty->buf[vty->cp];
		c2 = vty->buf[vty->cp - 1];

		vty_backward_char (vty);
		vty_self_insert_overwrite (vty, c1);
		vty_self_insert_overwrite (vty, c2);
	}

	return;
}

static void vty_previous_line (struct _vty *vty)
{
	int try_index;

	try_index = vty->hp;
	if (try_index == 0)
		try_index = VTY_HIST_CMD_SIZE - 1;
	else
		try_index--;

	if (vty->hist[try_index] == NULL)
		return;
	else
		vty->hp = try_index;

	vty_history_print (vty);
	return;
}

static void vty_next_line (struct _vty *vty)
{
	int try_index;

	if (vty->hp == vty->hindex)
		return;

	try_index = vty->hp;
	if (try_index == (VTY_HIST_CMD_SIZE - 1))
		try_index = 0;
	else
		try_index++;

	if (vty->hist[try_index] == NULL)
		return;
	else
		vty->hp = try_index;

	vty_history_print (vty);
	return;
}

static void vty_hist_add (struct _vty *vty)
{
	int index;

	if (vty->length == 0)
		return;

	index = vty->hindex ? vty->hindex - 1 : VTY_HIST_CMD_SIZE - 1;

	if (vty->hist[index])
		if (strcmp (vty->buf, vty->hist[index]) == 0) {
		vty->hp = vty->hindex;
		return;
		}

	if (vty->hist[vty->hindex])
		free (vty->hist[vty->hindex]);
	vty->hist[vty->hindex] = strdup ( vty->buf);

	vty->hindex++;
	if (vty->hindex == VTY_HIST_CMD_SIZE)
		vty->hindex = 0;

	vty->hp = vty->hindex;
	return;
}

vector
cmd_make_strvec (const char *string)
{
  const char *cp, *start;
  char *token;
  int strlen;
  vector strvec;
  
  if (string == NULL)
    return NULL;
  
  cp = string;

  /* Skip white spaces. */
  while (isspace ((int) *cp) && *cp != '\0')
    cp++;

  /* Return if there is only white spaces */
  if (*cp == '\0')
    return NULL;

  if (*cp == '!' || *cp == '#')
    return NULL;

  /* Prepare return vector. */
  strvec = vector_init ();

  /* Copy each command piece and set into vector. */
  while (1) 
    {
      start = cp;
      while (!(isspace ((int) *cp) || *cp == '\r' || *cp == '\n') &&
	     *cp != '\0')
	cp++;
      strlen = cp - start;
      token = calloc (1, strlen + 1);
      memcpy (token, start, strlen);
      *(token + strlen) = '\0';
      vector_set (strvec, token);

      while ((isspace ((int) *cp) || *cp == '\n' || *cp == '\r') &&
	     *cp != '\0')
	cp++;

      if (*cp == '\0')
	return strvec;
    }
}

void *vector_lookup (vector v, unsigned int i)
{
  if (i >= v->active)
    return NULL;
  return v->index[i];
}

unsigned int vector_count (vector v)
{
  unsigned int i;
  unsigned count = 0;

  for (i = 0; i < v->active; i++) 
    if (v->index[i] != NULL)
      count++;

  return count;
}

vector vector_copy (vector v)
{
  unsigned int size;
  vector new = calloc (1, sizeof (struct _vector));

  new->active = v->active;
  new->alloced = v->alloced;

  size = sizeof (void *) * (v->alloced);
  new->index = calloc (1, size);
  memcpy (new->index, v->index, size);

  return new;
}

static vector cmd_node_vector (vector v, unsigned int ntype)
{
  struct cmd_node *cnode = vector_slot (v, ntype);
  return cnode->cmd_vector;
}

static void cmd_matcher_init(struct cmd_matcher *matcher,
                 struct cmd_element *cmd,
                 enum filter_type filter,
                 vector vline,
                 unsigned int index,
                 enum match_type *match_type,
                 vector *match)
{
  memset(matcher, 0, sizeof(*matcher));

  matcher->cmd = cmd;
  matcher->filter = filter;
  matcher->vline = vline;
  matcher->index = index;

  matcher->_match_type = match_type;
  if (matcher->_match_type)
    *matcher->_match_type = no_match;
  matcher->match = match;

  matcher->word_index = 0;
}

static int cmd_range_match (const char *range, const char *str)
{
char *p;
char buf[DECIMAL_STRLEN_MAX + 1];
char *endptr = NULL;
unsigned long min, max, val;

if (str == NULL)
 return 1;

val = strtoul (str, &endptr, 10);
if (*endptr != '\0')
 return 0;

range++;
p = strchr (range, '-');
if (p == NULL)
 return 0;
if (p - range > DECIMAL_STRLEN_MAX)
 return 0;
strncpy (buf, range, p - range);
buf[p - range] = '\0';
min = strtoul (buf, &endptr, 10);
if (*endptr != '\0')
 return 0;

range = p + 1;
p = strchr (range, '>');
if (p == NULL)
 return 0;
if (p - range > DECIMAL_STRLEN_MAX)
 return 0;
strncpy (buf, range, p - range);
buf[p - range] = '\0';
max = strtoul (buf, &endptr, 10);
if (*endptr != '\0')
 return 0;

if (val < min || val > max)
 return 0;

return 1;
}

static enum match_type cmd_ipv6_match (const char *str)
{
  struct sockaddr_in6 sin6_dummy;
  int ret;

  if (str == NULL)
    return partly_match;

  if (strspn (str, IPV6_ADDR_STR) != strlen (str))
    return no_match;

  /* use inet_pton that has a better support,
   * for example inet_pton can support the automatic addresses:
   *  ::1.2.3.4
   */
  ret = inet_pton(AF_INET6, str, &sin6_dummy.sin6_addr);
   
  if (ret == 1)
    return exact_match;

  return no_match;
}

static enum match_type cmd_ipv6_prefix_match (const char *str)
{
  int state = STATE_START;
  int colons = 0, nums = 0, double_colon = 0;
  int mask;
  const char *sp = NULL;
  char *endptr = NULL;

  if (str == NULL)
    return partly_match;

  if (strspn (str, IPV6_PREFIX_STR) != strlen (str))
    return no_match;

  while (*str != '\0' && state != STATE_MASK)
    {
      switch (state)
	{
	case STATE_START:
	  if (*str == ':')
	    {
	      if (*(str + 1) != ':' && *(str + 1) != '\0')
		return no_match;
	      colons--;
	      state = STATE_COLON;
	    }
	  else
	    {
	      sp = str;
	      state = STATE_ADDR;
	    }

	  continue;
	case STATE_COLON:
	  colons++;
	  if (*(str + 1) == '/')
	    return no_match;
	  else if (*(str + 1) == ':')
	    state = STATE_DOUBLE;
	  else
	    {
	      sp = str + 1;
	      state = STATE_ADDR;
	    }
	  break;
	case STATE_DOUBLE:
	  if (double_colon)
	    return no_match;

	  if (*(str + 1) == ':')
	    return no_match;
	  else
	    {
	      if (*(str + 1) != '\0' && *(str + 1) != '/')
		colons++;
	      sp = str + 1;

	      if (*(str + 1) == '/')
		state = STATE_SLASH;
	      else
		state = STATE_ADDR;
	    }

	  double_colon++;
	  nums += 1;
	  break;
	case STATE_ADDR:
	  if (*(str + 1) == ':' || *(str + 1) == '.'
	      || *(str + 1) == '\0' || *(str + 1) == '/')
	    {
	      if (str - sp > 3)
		return no_match;

	      for (; sp <= str; sp++)
		if (*sp == '/')
		  return no_match;

	      nums++;

	      if (*(str + 1) == ':')
		state = STATE_COLON;
	      else if (*(str + 1) == '.')
		{
		  if (colons || double_colon)
		    state = STATE_DOT;
		  else
		    return no_match;
		}
	      else if (*(str + 1) == '/')
		state = STATE_SLASH;
	    }
	  break;
	case STATE_DOT:
	  state = STATE_ADDR;
	  break;
	case STATE_SLASH:
	  if (*(str + 1) == '\0')
	    return partly_match;

	  state = STATE_MASK;
	  break;
	default:
	  break;
	}

      if (nums > 11)
	return no_match;

      if (colons > 7)
	return no_match;

      str++;
    }

  if (state < STATE_MASK)
    return partly_match;

  mask = strtol (str, &endptr, 10);
  if (*endptr != '\0')
    return no_match;

  if (mask < 0 || mask > 128)
    return no_match;
  
  return exact_match;
}

static enum match_type cmd_ipv4_prefix_match (const char *str)
{
  const char *sp;
  int dots = 0;
  char buf[4];

  if (str == NULL)
    return partly_match;

  for (;;)
    {
      memset (buf, 0, sizeof (buf));
      sp = str;
      while (*str != '\0' && *str != '/')
	{
	  if (*str == '.')
	    {
	      if (dots == 3)
		return no_match;

	      if (*(str + 1) == '.' || *(str + 1) == '/')
		return no_match;

	      if (*(str + 1) == '\0')
		return partly_match;

	      dots++;
	      break;
	    }

	  if (!isdigit ((int) *str))
	    return no_match;

	  str++;
	}

      if (str - sp > 3)
	return no_match;

      strncpy (buf, sp, str - sp);
      if (atoi (buf) > 255)
	return no_match;

      if (dots == 3)
	{
	  if (*str == '/')
	    {
	      if (*(str + 1) == '\0')
		return partly_match;

	      str++;
	      break;
	    }
	  else if (*str == '\0')
	    return partly_match;
	}

      if (*str == '\0')
	return partly_match;

      str++;
    }

  sp = str;
  while (*str != '\0')
    {
      if (!isdigit ((int) *str))
	return no_match;

      str++;
    }

  if (atoi (sp) > 32)
    return no_match;

  return exact_match;
}

static enum match_type cmd_ipv4_match (const char *str)
{
  const char *sp;
  int dots = 0, nums = 0;
  char buf[4];

  if (str == NULL)
    return partly_match;

  for (;;)
    {
      memset (buf, 0, sizeof (buf));
      sp = str;
      while (*str != '\0')
	{
	  if (*str == '.')
	    {
	      if (dots >= 3)
		return no_match;

	      if (*(str + 1) == '.')
		return no_match;

	      if (*(str + 1) == '\0')
		return partly_match;

	      dots++;
	      break;
	    }
	  if (!isdigit ((int) *str))
	    return no_match;

	  str++;
	}

      if (str - sp > 3)
	return no_match;

      strncpy (buf, sp, str - sp);
      if (atoi (buf) > 255)
	return no_match;

      nums++;

      if (*str == '\0')
	break;

      str++;
    }

  if (nums < 4)
    return partly_match;

  return exact_match;
}

static enum match_type cmd_word_match(struct cmd_token *token,
			enum filter_type filter,
			const char *word)
{
const char *str;
enum match_type match_type;

str = token->cmd;

if (filter == FILTER_RELAXED)
 if (!word || !strlen(word))
   return partly_match;

if (!word)
 return no_match;

switch (token->terminal)
 {
   case TERMINAL_VARARG:
	 return vararg_match;

   case TERMINAL_RANGE:
	 if (cmd_range_match(str, word))
	   return range_match;
	 break;

   case TERMINAL_IPV6:
	 match_type = cmd_ipv6_match(word);
	 if ((filter == FILTER_RELAXED && match_type != no_match)
	   || (filter == FILTER_STRICT && match_type == exact_match))
	   return ipv6_match;
	 break;

   case TERMINAL_IPV6_PREFIX:
	 match_type = cmd_ipv6_prefix_match(word);
	 if ((filter == FILTER_RELAXED && match_type != no_match)
		 || (filter == FILTER_STRICT && match_type == exact_match))
	   return ipv6_prefix_match;
	 break;

   case TERMINAL_IPV4:
	 match_type = cmd_ipv4_match(word);
	 if ((filter == FILTER_RELAXED && match_type != no_match)
		 || (filter == FILTER_STRICT && match_type == exact_match))
	   return ipv4_match;
	 break;

   case TERMINAL_IPV4_PREFIX:
	 match_type = cmd_ipv4_prefix_match(word);
	 if ((filter == FILTER_RELAXED && match_type != no_match)
		 || (filter == FILTER_STRICT && match_type == exact_match))
	   return ipv4_prefix_match;
	 break;

   case TERMINAL_OPTION:
   case TERMINAL_VARIABLE:
	 return extend_match;

   case TERMINAL_LITERAL:
	 if (filter == FILTER_RELAXED && !strncmp(str, word, strlen(word)))
	   {
		 if (!strcmp(str, word))
		   return exact_match;
		 return partly_match;
	   }
	 if (filter == FILTER_STRICT && !strcmp(str, word))
	   return exact_match;
	 break;

   default:
		return no_match;
 }

return no_match;
}
static const char* cmd_matcher_get_word(struct cmd_matcher *matcher)
{
	return vector_slot(matcher->vline, matcher->word_index);
}

 static int cmd_matcher_words_left(struct cmd_matcher *matcher)
 {
   return matcher->word_index < vector_active(matcher->vline);
 }

 static int push_argument(int *argc, const char **argv, const char *arg)
 {
   if (!arg || !strlen(arg))
	 arg = NULL;
 
   if (!argc || !argv)
	 return 0;
 
   if (*argc >= CMD_ARGC_MAX)
	 return -1;
 
   argv[(*argc)++] = arg;
   return 0;
 }

 static void cmd_matcher_record_match(struct cmd_matcher *matcher,
						  enum match_type match_type,
						  struct cmd_token *token)
 {
   if (matcher->word_index != matcher->index)
	 return;
 
   if (matcher->match)
	 {
	   if (!*matcher->match)
		 *matcher->match = vector_init();
	   vector_set(*matcher->match, token);
	 }
 
   if (matcher->_match_type)
	 {
	   if (match_type > *matcher->_match_type)
		 *matcher->_match_type = match_type;
	 }
 }

 static enum matcher_rv cmd_matcher_match_terminal(struct cmd_matcher *matcher,
							struct cmd_token *token,
							int *argc, const char **argv)
 {
   const char *word;
   enum match_type word_match;
  
   if (!cmd_matcher_words_left(matcher))
	 {
	   if (token->terminal == TERMINAL_OPTION)
		 return MATCHER_OK; /* missing optional args are NOT pushed as NULL */
	   else
		 return MATCHER_INCOMPLETE;
	 }
 
   word = cmd_matcher_get_word(matcher);
   word_match = cmd_word_match(token, matcher->filter, word);
   if (word_match == no_match)
	 return MATCHER_NO_MATCH;
 
   /* We have to record the input word as argument if it matched
	* against a variable. */
   if (TERMINAL_RECORD (token->terminal))
	 {
	   if (push_argument(argc, argv, word))
		 return MATCHER_EXCEED_ARGC_MAX;
	 }
 
   cmd_matcher_record_match(matcher, word_match, token);
 
   matcher->word_index++;
 
   /* A vararg token should consume all left over words as arguments */
   if (token->terminal == TERMINAL_VARARG)
	 while (cmd_matcher_words_left(matcher))
	   {
		 word = cmd_matcher_get_word(matcher);
		 if (word && strlen(word))
		   push_argument(argc, argv, word);
		 matcher->word_index++;
	   }
 
   return MATCHER_OK;
 }


static enum matcher_rv cmd_matcher_match_multiple(struct cmd_matcher *matcher,
						   struct cmd_token *token,
						   int *argc, const char **argv)
{
  enum match_type multiple_match;
  unsigned int multiple_index;
  const char *word;
  const char *arg = NULL;
  struct cmd_token *word_token;
  enum match_type word_match;

  multiple_match = no_match;

  if (!cmd_matcher_words_left(matcher))
	return MATCHER_INCOMPLETE;

  word = cmd_matcher_get_word(matcher);
  for (multiple_index = 0;
	   multiple_index < vector_active(token->multiple);
	   multiple_index++)
	{
	  word_token = vector_slot(token->multiple, multiple_index);

	  word_match = cmd_word_match(word_token, matcher->filter, word);
	  if (word_match == no_match)
		continue;

	  cmd_matcher_record_match(matcher, word_match, word_token);

	  if (word_match > multiple_match)
		{
		  multiple_match = word_match;
		  arg = word;
		}
	  /* To mimic the behavior of the old command implementation, we
	   * tolerate any ambiguities here :/ */
	}

  matcher->word_index++;

  if (multiple_match == no_match)
	return MATCHER_NO_MATCH;

  if (push_argument(argc, argv, arg))
	return MATCHER_EXCEED_ARGC_MAX;

  return MATCHER_OK;
}

static enum matcher_rv cmd_matcher_read_keywords(struct cmd_matcher *matcher,
						 struct cmd_token *token,
						 vector args_vector)
{
 unsigned int i;
 unsigned long keyword_mask;
 unsigned int keyword_found;
 enum match_type keyword_match;
 enum match_type word_match;
 vector keyword_vector;
 struct cmd_token *word_token;
 const char *word;
 int keyword_argc;
 const char **keyword_argv;
 enum matcher_rv rv = MATCHER_NO_MATCH;

 keyword_mask = 0;
 while (1)
   {
	 if (!cmd_matcher_words_left(matcher))
	   return MATCHER_OK;

	 word = cmd_matcher_get_word(matcher);

	 keyword_found = -1;
	 keyword_match = no_match;
	 for (i = 0; i < vector_active(token->keyword); i++)
	   {
		 if (keyword_mask & (1 << i))
		   continue;

		 keyword_vector = vector_slot(token->keyword, i);
		 word_token = vector_slot(keyword_vector, 0);

		 word_match = cmd_word_match(word_token, matcher->filter, word);
		 if (word_match == no_match)
		   continue;

		 cmd_matcher_record_match(matcher, word_match, word_token);

		 if (word_match > keyword_match)
		   {
			 keyword_match = word_match;
			 keyword_found = i;
		   }
		 else if (word_match == keyword_match)
		   {
			 if (matcher->word_index != matcher->index || args_vector)
			   return MATCHER_AMBIGUOUS;
		   }
	   }

	 if (keyword_found == (unsigned int)-1)
	   return MATCHER_NO_MATCH;

	 matcher->word_index++;

	 if (matcher->word_index > matcher->index)
	   return MATCHER_OK;

	 keyword_mask |= (1 << keyword_found);

	 if (args_vector)
	   {
		 keyword_argc = 0;
		 keyword_argv = calloc(1, (CMD_ARGC_MAX + 1) * sizeof(char*));
		 /* We use -1 as a marker for unused fields as NULL might be a valid value */
		 for (i = 0; i < CMD_ARGC_MAX + 1; i++)
		   keyword_argv[i] = (void*)-1;
		 vector_set_index(args_vector, keyword_found, keyword_argv);
	   }
	 else
	   {
		 keyword_argv = NULL;
	   }

	 keyword_vector = vector_slot(token->keyword, keyword_found);
	 /* the keyword itself is at 0. We are only interested in the arguments,
	  * so start counting at 1. */
	 for (i = 1; i < vector_active(keyword_vector); i++)
	   {
		 word_token = vector_slot(keyword_vector, i);

		 switch (word_token->type)
		   {
		   case TOKEN_TERMINAL:
			 rv = cmd_matcher_match_terminal(matcher, word_token,
											 &keyword_argc, keyword_argv);
			 break;
		   case TOKEN_MULTIPLE:
			 rv = cmd_matcher_match_multiple(matcher, word_token,
											 &keyword_argc, keyword_argv);
			 break;
		   case TOKEN_KEYWORD:
			 break;
		   }

		 if (MATCHER_ERROR(rv))
		   return rv;

		 if (matcher->word_index > matcher->index)
		   return MATCHER_OK;
	   }
   }
 /* not reached */
}

void vector_free (vector v)
{
free ( v->index);
free ( v);
}

static enum matcher_rv cmd_matcher_build_keyword_args(struct cmd_matcher *matcher,
							struct cmd_token *token,
							int *argc, const char **argv,
							vector keyword_args_vector)
{
unsigned int i, j;
const char **keyword_args;
vector keyword_vector;
struct cmd_token *word_token;
const char *arg;
enum matcher_rv rv;

rv = MATCHER_OK;

if (keyword_args_vector == NULL)
 return rv;

for (i = 0; i < vector_active(token->keyword); i++)
 {
   keyword_vector = vector_slot(token->keyword, i);
   keyword_args = vector_lookup(keyword_args_vector, i);

   if (vector_active(keyword_vector) == 1)
	 {
	   /* this is a keyword without arguments */
	   if (keyword_args)
		 {
		   word_token = vector_slot(keyword_vector, 0);
		   arg = word_token->cmd;
		 }
	   else
		 {
		   arg = NULL;
		 }

	   if (push_argument(argc, argv, arg))
		 rv = MATCHER_EXCEED_ARGC_MAX;
	 }
   else
	 {
	   /* this is a keyword with arguments */
	   if (keyword_args)
		 {
		   /* the keyword was present, so just fill in the arguments */
		   for (j = 0; keyword_args[j] != (void*)-1; j++)
			 if (push_argument(argc, argv, keyword_args[j]))
			   rv = MATCHER_EXCEED_ARGC_MAX;
		   free( keyword_args);
		 }
	   else
		 {
		   /* the keyword was not present, insert NULL for the arguments
			* the keyword would have taken. */
		   for (j = 1; j < vector_active(keyword_vector); j++)
			 {
			   word_token = vector_slot(keyword_vector, j);
			   if ((word_token->type == TOKEN_TERMINAL
					&& TERMINAL_RECORD (word_token->terminal))
				   || word_token->type == TOKEN_MULTIPLE)
				 {
				   if (push_argument(argc, argv, NULL))
					 rv = MATCHER_EXCEED_ARGC_MAX;
				 }
			 }
		 }
	 }
 }
vector_free(keyword_args_vector);
return rv;
}
static enum matcher_rv cmd_matcher_match_keyword(struct cmd_matcher *matcher,
						 struct cmd_token *token,
						 int *argc, const char **argv)
{
 vector keyword_args_vector;
 enum matcher_rv reader_rv;
 enum matcher_rv builder_rv;

 if (argc && argv)
   keyword_args_vector = vector_init();
 else
   keyword_args_vector = NULL;

 reader_rv = cmd_matcher_read_keywords(matcher, token, keyword_args_vector);
 builder_rv = cmd_matcher_build_keyword_args(matcher, token, argc,
											 argv, keyword_args_vector);
 /* keyword_args_vector is consumed by cmd_matcher_build_keyword_args */

 if (!MATCHER_ERROR(reader_rv) && MATCHER_ERROR(builder_rv))
   return builder_rv;

 return reader_rv;
}

static enum matcher_rv cmd_element_match(struct cmd_element *cmd_element,
                  enum filter_type filter,
                  vector vline,
                  unsigned int index,
                  enum match_type *match_type,
                  vector *match,
                  int *argc,
                  const char **argv)
{
  struct cmd_matcher matcher;
  unsigned int token_index;
  enum matcher_rv rv = MATCHER_NO_MATCH;

  cmd_matcher_init(&matcher, cmd_element, filter,
                   vline, index, match_type, match);

  if (argc != NULL)
    *argc = 0;

  for (token_index = 0;
       token_index < vector_active(cmd_element->tokens);
       token_index++)
    {
      struct cmd_token *token = vector_slot(cmd_element->tokens, token_index);

      switch (token->type)
        {
        case TOKEN_TERMINAL:
          rv = cmd_matcher_match_terminal(&matcher, token, argc, argv);
          break;
        case TOKEN_MULTIPLE:
          rv = cmd_matcher_match_multiple(&matcher, token, argc, argv);
          break;
        case TOKEN_KEYWORD:
          rv = cmd_matcher_match_keyword(&matcher, token, argc, argv);
        }

      if (MATCHER_ERROR(rv))
        return rv;

      if (matcher.word_index > index)
        return MATCHER_OK;
    }

  /* return MATCHER_COMPLETE if all words were consumed */
  if (matcher.word_index >= vector_active(vline))
    return MATCHER_COMPLETE;

  /* return MATCHER_COMPLETE also if only an empty word is left. */
  if (matcher.word_index == vector_active(vline) - 1
      && (!vector_slot(vline, matcher.word_index)
          || !strlen((char*)vector_slot(vline, matcher.word_index))))
    return MATCHER_COMPLETE;

  return MATCHER_NO_MATCH; /* command is too long to match */
}

static int cmd_vector_filter(vector commands,
                  enum filter_type filter,
                  vector vline,
                  unsigned int index,
                  enum match_type *match_type,
                  vector *matches)
{
  unsigned int i;
  struct cmd_element *cmd_element;
  enum match_type best_match;
  enum match_type element_match;
  enum matcher_rv matcher_rv;

  best_match = no_match;
  *matches = vector_init();

  for (i = 0; i < vector_active (commands); i++)
    if ((cmd_element = vector_slot (commands, i)) != NULL)
      {
        vector_set_index(*matches, i, NULL);
        matcher_rv = cmd_element_match(cmd_element, filter,
                                       vline, index,
                                       &element_match,
                                       (vector*)&vector_slot(*matches, i),
                                       NULL, NULL);
        if (MATCHER_ERROR(matcher_rv))
          {
            vector_slot(commands, i) = NULL;
            if (matcher_rv == MATCHER_AMBIGUOUS)
              return CMD_ERR_AMBIGUOUS;
            if (matcher_rv == MATCHER_EXCEED_ARGC_MAX)
              return CMD_ERR_EXEED_ARGC_MAX;
          }
        else if (element_match > best_match)
          {
            best_match = element_match;
          }
      }
  *match_type = best_match;
  return CMD_SUCCESS;
}

static void cmd_matches_free(vector *matches)
{
unsigned int i;
vector cmd_matches;

for (i = 0; i < vector_active(*matches); i++)
  if ((cmd_matches = vector_slot(*matches, i)) != NULL)
	vector_free(cmd_matches);
vector_free(*matches);
*matches = NULL;
}

static int is_cmd_ambiguous (vector cmd_vector,
                  const char *command,
                  vector matches,
                  enum match_type type)
{
  unsigned int i;
  unsigned int j;
  const char *str = NULL;
  const char *matched = NULL;
  vector match_vector;
  struct cmd_token *cmd_token;

  if (command == NULL)
    command = "";

  for (i = 0; i < vector_active (matches); i++)
    if ((match_vector = vector_slot (matches, i)) != NULL)
      {
	int match = 0;

	for (j = 0; j < vector_active (match_vector); j++)
	  if ((cmd_token = vector_slot (match_vector, j)) != NULL)
	    {
	      enum match_type ret;

	      if (cmd_token->type != TOKEN_TERMINAL)
		continue;

	      str = cmd_token->cmd;

	      switch (type)
		{
		case exact_match:
		  if (!TERMINAL_RECORD (cmd_token->terminal)
		      && strcmp (command, str) == 0)
		    match++;
		  break;
		case partly_match:
		  if (!TERMINAL_RECORD (cmd_token->terminal)
		      && strncmp (command, str, strlen (command)) == 0)
		    {
		      if (matched && strcmp (matched, str) != 0)
			return 1;	/* There is ambiguous match. */
		      else
			matched = str;
		      match++;
		    }
		  break;
		case range_match:
		  if (cmd_range_match (str, command))
		    {
		      if (matched && strcmp (matched, str) != 0)
			return 1;
		      else
			matched = str;
		      match++;
		    }
		  break;
		case ipv6_match:
		  if (cmd_token->terminal == TERMINAL_IPV6)
		    match++;
		  break;
		case ipv6_prefix_match:
		  if ((ret = cmd_ipv6_prefix_match (command)) != no_match)
		    {
		      if (ret == partly_match)
			return 2;	/* There is incomplete match. */

		      match++;
		    }
		  break;
		case ipv4_match:
		  if (cmd_token->terminal == TERMINAL_IPV4)
		    match++;
		  break;
		case ipv4_prefix_match:
		  if ((ret = cmd_ipv4_prefix_match (command)) != no_match)
		    {
		      if (ret == partly_match)
			return 2;	/* There is incomplete match. */

		      match++;
		    }
		  break;
		case extend_match:
		  if (TERMINAL_RECORD (cmd_token->terminal))
		    match++;
		  break;
		case no_match:
		default:
		  break;
		}
	    }
	if (!match)
	  vector_slot (cmd_vector, i) = NULL;
      }
  return 0;
}

static int cmd_is_complete(struct cmd_element *cmd_element,
			  vector vline)
{
enum matcher_rv rv;

rv = cmd_element_match(cmd_element,
					   FILTER_RELAXED,
					   vline, -1,
					   NULL, NULL,
					   NULL, NULL);
return (rv == MATCHER_COMPLETE);
}

static int cmd_parse(struct cmd_element *cmd_element,
		vector vline,
		int *argc, const char **argv)
{
enum matcher_rv rv = cmd_element_match(cmd_element,
									   FILTER_RELAXED,
									   vline, -1,
									   NULL, NULL,
									   argc, argv);
switch (rv)
  {
  case MATCHER_COMPLETE:
	return CMD_SUCCESS;

  case MATCHER_NO_MATCH:
	return CMD_ERR_NO_MATCH;

  case MATCHER_AMBIGUOUS:
	return CMD_ERR_AMBIGUOUS;

  case MATCHER_EXCEED_ARGC_MAX:
	return CMD_ERR_EXEED_ARGC_MAX;

  default:
	return CMD_ERR_INCOMPLETE;
  }
}

static int cmd_execute_command_real (vector vline,
			  enum filter_type filter,
			  struct _vty *vty,
			  struct cmd_element **cmd)
{
  unsigned int i;
  unsigned int index;
  vector cmd_vector;
  struct cmd_element *cmd_element;
  struct cmd_element *matched_element;
  unsigned int matched_count, incomplete_count;
  int argc;
  const char *argv[CMD_ARGC_MAX];
  enum match_type match = 0;
  char *command;
  int ret;
  vector matches;

  /* Make copy of command elements. */
  cmd_vector = vector_copy (cmd_node_vector (cmdvec, vty->node));

  for (index = 0; index < vector_active (vline); index++)
    {
      command = vector_slot (vline, index);
      ret = cmd_vector_filter(cmd_vector,
			      filter,
			      vline, index,
			      &match,
			      &matches);

      if (ret != CMD_SUCCESS)
	{
	  cmd_matches_free(&matches);
	  return ret;
	}

      if (match == vararg_match)
	{
	  cmd_matches_free(&matches);
	  break;
	}

      ret = is_cmd_ambiguous (cmd_vector, command, matches, match);
      cmd_matches_free(&matches);

      if (ret == 1)
	{
	  vector_free(cmd_vector);
	  return CMD_ERR_AMBIGUOUS;
	}
      else if (ret == 2)
	{
	  vector_free(cmd_vector);
	  return CMD_ERR_NO_MATCH;
	}
    }

  /* Check matched count. */
  matched_element = NULL;
  matched_count = 0;
  incomplete_count = 0;

  for (i = 0; i < vector_active (cmd_vector); i++)
    if ((cmd_element = vector_slot (cmd_vector, i)))
      {
	if (cmd_is_complete(cmd_element, vline))
	  {
	    matched_element = cmd_element;
	    matched_count++;
	  }
	else
	  {
	    incomplete_count++;
	  }
      }

  /* Finish of using cmd_vector. */
  vector_free (cmd_vector);

  /* To execute command, matched_count must be 1. */
  if (matched_count == 0)
    {
      if (incomplete_count)
	return CMD_ERR_INCOMPLETE;
      else
	return CMD_ERR_NO_MATCH;
    }

  if (matched_count > 1)
    return CMD_ERR_AMBIGUOUS;

  ret = cmd_parse(matched_element, vline, &argc, argv);
  if (ret != CMD_SUCCESS)
    return ret;

  /* For vtysh execution. */
  if (cmd)
    *cmd = matched_element;

  if (matched_element->daemon)
    return CMD_SUCCESS_DAEMON;

  /* Execute matched command. */
  return (*matched_element->cb) (argc, argv, matched_element, vty);
}

int cmd_execute_command (vector vline, struct _vty *vty, struct cmd_element **cmd,int vtysh) 
{
int ret, saved_ret, tried = 0;
unsigned int onode, try_node;
vector shifted_vline;
unsigned int index;

onode = try_node = vty->node;

if ( cmd_try_do_shortcut(vty->node, vector_slot(vline, 0) ) )
  {


	/* We can try it on enable node, cos' the vty is authenticated */

	shifted_vline = vector_init ();
	/* use memcpy? */
	for (index = 1; index < vector_active (vline); index++) 
  {
	vector_set_index (shifted_vline, index-1, vector_lookup(vline, index));
  }

	ret = cmd_execute_command_real (shifted_vline, FILTER_RELAXED, vty, cmd);

	vector_free(shifted_vline);
	vty->node = onode;
	return ret;
}


saved_ret = ret = cmd_execute_command_real (vline, FILTER_RELAXED, vty, cmd);

if (vtysh)
  return saved_ret;

/* no command succeeded, reset the vty to the original node and
   return the error for this node */
if ( tried )
  vty->node = onode;
return saved_ret;
}


void cmd_free_strvec (vector v)
{
  unsigned int i;
  char *cp;

  if (!v)
    return;

  for (i = 0; i < vector_active (v); i++)
    if ((cp = vector_slot (v, i)) != NULL)
      free (cp);

  vector_free (v);
}

static int vty_command (struct _vty *vty, char *buf)
{
  int ret;
  vector vline;

  /* Split readline string up into the vector */
  vline = cmd_make_strvec (buf);

  if (vline == NULL)
    return 0;

  ret = cmd_execute_command (vline, vty, NULL, 0);

  if (ret != CMD_SUCCESS)
    switch (ret)
      {
      case CMD_WARNING:
	if (vty->type == VTY_FILE)
	  vty_out (vty, "Warning...%s", VTY_NEWLINE);
	break;
      case CMD_ERR_AMBIGUOUS:
	vty_out (vty, "%% Ambiguous command.%s", VTY_NEWLINE);
	break;
      case CMD_ERR_NO_MATCH:
	vty_out (vty, "%% Unknown command: %s%s", buf, VTY_NEWLINE);
	break;
      case CMD_ERR_INCOMPLETE:
	vty_out (vty, "%% Command incomplete.%s", VTY_NEWLINE);
	break;
      }
  cmd_free_strvec (vline);

  return ret;
}

static int vty_execute (struct _vty *vty)
{
  int ret;

  ret = 0;

  switch (vty->node)
    {
    default:
      ret = vty_command (vty, vty->buf);
      if (vty->type == VTY_TERM)
		vty_hist_add (vty);
      break;
    }

  /* Clear command line buffer. */
  vty->cp = vty->length = 0;
  vty_clear_buf (vty);
if (vty->status != VTY_CLOSE)
  	vty_prompt (vty);

  return ret;
}

static void vty_backward_kill_word (struct _vty *vty)
{
  while (vty->cp > 0 && vty->buf[vty->cp - 1] == ' ')
    vty_delete_backward_char (vty);
  while (vty->cp > 0 && vty->buf[vty->cp - 1] != ' ')
    vty_delete_backward_char (vty);
}

static void vty_escape_map (unsigned char c, struct _vty *vty)
{
  switch (c)
    {
    case ('A'):
      vty_previous_line (vty);
      break;
    case ('B'):
      vty_next_line (vty);
      break;
    case ('C'):
      vty_forward_char (vty);
      break;
    case ('D'):
      vty_backward_char (vty);
      break;
    default:
      break;
    }

  /* Go back to normal mode. */
  vty->escape = VTY_NORMAL;
}


static struct _vty * vty_new_init (int vty_sock, unsigned int node_type)
{
  struct _vty *vty;

  vty = calloc(1, sizeof(*vty));
  vty->max = VTY_INPUT_BUF_SIZE;
  vty->fd = vty_sock;
  vty->node = node_type;
  vty->cp = 0;
  vty->length = 0;
  memset (vty->hist, 0, sizeof (vty->hist));
  vty->hp = 0;
  vty->hindex = 0;
  vty->fd = vty_sock;
  vty->iac = 0;
  vty->iac_sb_in_progress = 0;
  vty->sb_len = 0;
  vty->type = VTY_TERM;
  vty->status = VTY_NORMAL;
  return vty;
}

static void format_parser_begin_keyword(struct format_parser_state *state)
{
  struct cmd_token *token;
  vector keyword_vect;

  if (state->in_keyword
      || state->in_multiple)
    format_parser_error(state, "Unexpected '{'");

  state->cp++;
  state->in_keyword = 1;

  token = calloc(1, sizeof(*token));
  token->type = TOKEN_KEYWORD;
  token->keyword = vector_init();

  keyword_vect = vector_init();
  vector_set(token->keyword, keyword_vect);

  vector_set(state->curvect, token);
  state->curvect = keyword_vect;
}

 static void format_parser_begin_multiple(struct format_parser_state *state)
{
  struct cmd_token *token;

  if (state->in_keyword == 1)
    format_parser_error(state, "Keyword starting with '('");

  if (state->in_multiple)
    format_parser_error(state, "Nested group");

  state->cp++;
  state->in_multiple = 1;
  state->just_read_word = 0;

  token = calloc(1, sizeof(*token));
  token->type = TOKEN_MULTIPLE;
  token->multiple = vector_init();

  vector_set(state->curvect, token);
  if (state->curvect != state->topvect)
    state->intvect = state->curvect;
  state->curvect = token->multiple;
}

 static void format_parser_end_keyword(struct format_parser_state *state)
 {
   if (state->in_multiple
	   || !state->in_keyword)
	 format_parser_error(state, "Unexpected '}'");
 
   if (state->in_keyword == 1)
	 format_parser_error(state, "Empty keyword group");
 
   state->cp++;
   state->in_keyword = 0;
   state->curvect = state->topvect;
 }

 static char * format_parser_desc_str(struct format_parser_state *state)
{
  const char *cp, *start;
  char *token;
  int strlen;

  cp = state->dp;

  if (cp == NULL)
    return NULL;

  /* Skip white spaces. */
  while (isspace ((int) *cp) && *cp != '\0')
    cp++;

  /* Return if there is only white spaces */
  if (*cp == '\0')
    return NULL;

  start = cp;

  while (!(*cp == '\r' || *cp == '\n') && *cp != '\0')
    cp++;

  strlen = cp - start;
  token = calloc (1, strlen + 1);
  memcpy (token, start, strlen);
  *(token + strlen) = '\0';

  state->dp = cp;

  return token;
}
 static void format_parser_end_multiple(struct format_parser_state *state)
 {
   char *dummy;
 
   if (!state->in_multiple)
	 format_parser_error(state, "Unexpected ')'");
 
   if (vector_active(state->curvect) == 0)
	 format_parser_error(state, "Empty multiple section");
 
   if (!state->just_read_word)
	 {
	   /* There are constructions like
		* 'show ip ospf database ... (self-originate|)'
		* in use.
		* The old parser reads a description string for the
		* word '' between |) which will never match.
		* Simulate this behvaior by dropping the next desc
		* string in such a case. */
 
	   dummy = format_parser_desc_str(state);
	   free( dummy);
	 }
 
   state->cp++;
   state->in_multiple = 0;
 
   if (state->intvect)
	 state->curvect = state->intvect;
   else
	 state->curvect = state->topvect;
 }
 
 static void format_parser_handle_pipe(struct format_parser_state *state)
 {
   struct cmd_token *keyword_token;
   vector keyword_vect;
 
   if (state->in_multiple)
	 {
	   state->just_read_word = 0;
	   state->cp++;
	 }
   else if (state->in_keyword)
	 {
	   state->in_keyword = 1;
	   state->cp++;
 
	   keyword_token = vector_slot(state->topvect,
								   vector_active(state->topvect) - 1);
	   keyword_vect = vector_init();
	   vector_set(keyword_token->keyword, keyword_vect);
	   state->curvect = keyword_vect;
	 }
   else
	 {
	   format_parser_error(state, "Unexpected '|'");
	 }
 }
 
 static void format_parser_read_word(struct format_parser_state *state)
 {
   const char *start;
   int len;
   char *cmd;
   struct cmd_token *token;
 
   start = state->cp;
 
   while (state->cp[0] != '\0'
		  && !strchr("\r\n(){}|", state->cp[0])
		  && !isspace((int)state->cp[0]))
	 state->cp++;
 
   len = state->cp - start;
   cmd = calloc(1, len + 1);
   memcpy(cmd, start, len);
   cmd[len] = '\0';
 
   token = calloc(1, sizeof(*token));
   token->type = TOKEN_TERMINAL;
   if (strcmp (cmd, "A.B.C.D") == 0)
	 token->terminal = TERMINAL_IPV4;
   else if (strcmp (cmd, "A.B.C.D/M") == 0)
	 token->terminal = TERMINAL_IPV4_PREFIX;
   else if (strcmp (cmd, "X:X::X:X") == 0)
	 token->terminal = TERMINAL_IPV6;
   else if (strcmp (cmd, "X:X::X:X/M") == 0)
	 token->terminal = TERMINAL_IPV6_PREFIX;
   else if (cmd[0] == '[')
	 token->terminal = TERMINAL_OPTION;
   else if (cmd[0] == '.')
	 token->terminal = TERMINAL_VARARG;
   else if (cmd[0] == '<')
	 token->terminal = TERMINAL_RANGE;
   else if (cmd[0] >= 'A' && cmd[0] <= 'Z')
	 token->terminal = TERMINAL_VARIABLE;
   else
	 token->terminal = TERMINAL_LITERAL;
 
   token->cmd = cmd;
   token->desc = format_parser_desc_str(state);
   vector_set(state->curvect, token);
 
   if (state->in_keyword == 1)
	 state->in_keyword = 2;
 
   state->just_read_word = 1;
 }

static vector cmd_parse_format(const char *string, const char *descstr)
{
  struct format_parser_state state;

  if (string == NULL)
    return NULL;

  memset(&state, 0, sizeof(state));
  state.topvect = state.curvect = vector_init();
  state.cp = state.string = string;
  state.dp = descstr;

  while (1)
    {
      while (isspace((int)state.cp[0]) && state.cp[0] != '\0')
        state.cp++;

      switch (state.cp[0])
        {
        case '\0':
          if (state.in_keyword
              || state.in_multiple)
            format_parser_error(&state, "Unclosed group/keyword");
          return state.topvect;
        case '{':
          format_parser_begin_keyword(&state);
          break;
        case '(':
          format_parser_begin_multiple(&state);
          break;
        case '}':
          format_parser_end_keyword(&state);
          break;
        case ')':
          format_parser_end_multiple(&state);
          break;
        case '|':
          format_parser_handle_pipe(&state);
          break;
        default:
          format_parser_read_word(&state);
        }
    }
}


int vty_init(vector *v)
{
	*v = vector_init ();
	cmdvec = *v;
	command_cr = strdup( "<cr>");
  token_cr.type = TOKEN_TERMINAL;
  token_cr.terminal = TERMINAL_LITERAL;
  token_cr.cmd = command_cr;
  token_cr.desc = strdup("");
	return 0;
}
void vty_exit(vector *v)
{
	return;
}



int  install_element (unsigned int ntype, struct cmd_element *cmd)
{
  struct cmd_node *cnode;
  
  /* cmd_init hasn't been called */
  if (!cmdvec)
    {
      fprintf (stderr, "%s called before cmd_init, breakage likely\n",
               __func__);
      return -1;
    }
  
  cnode = vector_slot (cmdvec, ntype);

  if (cnode == NULL) 
    {
      fprintf (stderr, "Command node %d doesn't exist, please check it\n",
	       ntype);
      return -1;
    }


  
  vector_set (cnode->cmd_vector, cmd);
  if (cmd->tokens == NULL)
    cmd->tokens = cmd_parse_format(cmd->string, cmd->doc);

  return 0;

}

int install_node (struct cmd_node *node)
{
  vector_set_index (cmdvec, node->node, node);
  node->cmd_vector = vector_init ();
  return 0;
}

static const char * cmd_entry_function (const char *src, struct cmd_token *token)
{
  const char *dst = token->cmd;

  /* Skip variable arguments. */
  if (TERMINAL_RECORD (token->terminal))
    return NULL;

  /* In case of 'command \t', given src is NULL string. */
  if (src == NULL)
    return dst;

  /* Matched with input string. */
  if (strncmp (src, dst, strlen (src)) == 0)
    return dst;

  return NULL;
}

static int cmd_unique_string (vector v, const char *str)
{
  unsigned int i;
  char *match;

  for (i = 0; i < vector_active (v); i++)
    if ((match = vector_slot (v, i)) != NULL)
      if (strcmp (match, str) == 0)
	return 0;
  return 1;
}

void vector_only_wrapper_free (vector v)
{
  free ( v);
}

static int cmd_lcd (char **matched)
{
  int i;
  int j;
  int lcd = -1;
  char *s1, *s2;
  char c1, c2;

  if (matched[0] == NULL || matched[1] == NULL)
    return 0;

  for (i = 1; matched[i] != NULL; i++)
    {
      s1 = matched[i - 1];
      s2 = matched[i];

      for (j = 0; (c1 = s1[j]) && (c2 = s2[j]); j++)
	if (c1 != c2)
	  break;

      if (lcd < 0)
	lcd = j;
      else
	{
	  if (lcd > j)
	    lcd = j;
	}
    }
  return lcd;
}

static int cmd_complete_cmp(const void *a, const void *b)
{
  const char *first = *(char * const *)a;
  const char *second = *(char * const *)b;

  if (!first)
    {
      if (!second)
        return 0;
      return 1;
    }
  if (!second)
    return -1;

  return strcmp(first, second);
}

static void cmd_complete_sort(vector matchvec)
{
  qsort(matchvec->index, vector_active(matchvec),
        sizeof(void*), cmd_complete_cmp);
}

static char ** cmd_complete_command_real (vector vline, struct _vty *vty, int *status, int islib)
{
  unsigned int i;
  vector cmd_vector = vector_copy (cmd_node_vector (cmdvec, vty->node));
#define INIT_MATCHVEC_SIZE 10
  vector matchvec;
  unsigned int index;
  char **match_str;
  struct cmd_token *token;
  char *command;
  int lcd;
  vector matches = NULL;
  vector match_vector;

  if (vector_active (vline) == 0)
    {
      vector_free (cmd_vector);
      *status = CMD_ERR_NO_MATCH;
      return NULL;
    }
  else
    index = vector_active (vline) - 1;

  /* First, filter by command string */
  for (i = 0; i <= index; i++)
    {
      command = vector_slot (vline, i);
      enum match_type match;
      int ret;

      if (matches)
        cmd_matches_free(&matches);

      /* First try completion match, if there is exactly match return 1 */
      ret = cmd_vector_filter(cmd_vector,
	                      FILTER_RELAXED,
	                      vline, i,
	                      &match,
	                      &matches);

      if (ret != CMD_SUCCESS)
	{
	  vector_free(cmd_vector);
	  cmd_matches_free(&matches);
	  *status = ret;
	  return NULL;
	}

      /* Break here - the completion mustn't be checked to be non-ambiguous */
      if (i == index)
	break;

      /* If there is exact match then filter ambiguous match else check
	 ambiguousness. */
      ret = is_cmd_ambiguous (cmd_vector, command, matches, match);
      if (ret == 1)
	{
	  vector_free (cmd_vector);
	  cmd_matches_free(&matches);
	  *status = CMD_ERR_AMBIGUOUS;
	  return NULL;
	}
    }
  
  /* Prepare match vector. */
  matchvec = vector_init ();

  /* Build the possible list of continuations into a list of completions */
  for (i = 0; i < vector_active (matches); i++)
    if ((match_vector = vector_slot (matches, i)))
      {
	const char *string;
	unsigned int j;

	for (j = 0; j < vector_active (match_vector); j++)
	  if ((token = vector_slot (match_vector, j)))
            {
              string = cmd_entry_function (vector_slot (vline, index), token);
              if (string && cmd_unique_string (matchvec, string))
                vector_set (matchvec, strdup (string));
            }
      }

  /* We don't need cmd_vector any more. */
  vector_free (cmd_vector);
  cmd_matches_free(&matches);

  /* No matched command */
  if (vector_slot (matchvec, 0) == NULL)
    {
      vector_free (matchvec);

      /* In case of 'command \t' pattern.  Do you need '?' command at
         the end of the line. */
      if (vector_slot (vline, index) == NULL)
	*status = CMD_ERR_NOTHING_TODO;
      else
	*status = CMD_ERR_NO_MATCH;
      return NULL;
    }

  /* Only one matched */
  if (vector_slot (matchvec, 1) == NULL)
    {
      match_str = (char **) matchvec->index;
      vector_only_wrapper_free (matchvec);
      *status = CMD_COMPLETE_FULL_MATCH;
      return match_str;
    }
  /* Make it sure last element is NULL. */
  vector_set (matchvec, NULL);

  /* Check LCD of matched strings. */
  if (vector_slot (vline, index) != NULL)
    {
      lcd = cmd_lcd ((char **) matchvec->index);

      if (lcd)
	{
	  int len = strlen (vector_slot (vline, index));

	  if (len < lcd)
	    {
	      char *lcdstr;

	      lcdstr = calloc(1,lcd + 1);
	      memcpy (lcdstr, matchvec->index[0], lcd);
	      lcdstr[lcd] = '\0';

	      /* Free matchvec. */
	      for (i = 0; i < vector_active (matchvec); i++)
                {
                  if (vector_slot (matchvec, i))
                    {
                        free (vector_slot (matchvec, i));
                    }
                }
	      vector_free (matchvec);

	      /* Make new matchvec. */
	      matchvec = vector_init ();
	      vector_set (matchvec, lcdstr);
	      match_str = (char **) matchvec->index;
	      vector_only_wrapper_free (matchvec);

	      *status = CMD_COMPLETE_MATCH;
	      return match_str;
	    }
	}
    }

  match_str = (char **) matchvec->index;
  cmd_complete_sort(matchvec);
  vector_only_wrapper_free (matchvec);
  *status = CMD_COMPLETE_LIST_MATCH;
  return match_str;
}

char ** cmd_complete_command_lib (vector vline, struct _vty *vty, int *status, int islib)
{
  char **ret;

  unsigned int onode;
  vector shifted_vline;
  unsigned int index;

  if ( cmd_try_do_shortcut(vty->node, vector_slot(vline, 0) ) ) {
	  onode = vty->node;
	 // vty->node = ENABLE_NODE;
	  /* We can try it on enable node, cos' the vty is authenticated */

	  shifted_vline = vector_init ();
	  /* use memcpy? */
	  for (index = 1; index < vector_active (vline); index++) 
	{
	  vector_set_index (shifted_vline, index-1, vector_lookup(vline, index));
	}

	  ret = cmd_complete_command_real (shifted_vline, vty, status, islib);

	  vector_free(shifted_vline);
	  vty->node = onode;
	  return ret;
  }

  return cmd_complete_command_real (vline, vty, status, islib);

}

static void vty_insert_word_overwrite (struct _vty *vty, char *str)
{
  
  #define MIN(a,b) ((a)<(b)?(a):(b))
  size_t nwrite = MIN ((int) strlen (str), vty->max - vty->cp - 1);
  memcpy (&vty->buf[vty->cp], str, nwrite);
  vty->cp += nwrite;
  vty->length = vty->cp;
  vty->buf[vty->length] = '\0';
  
  vty_write (vty, str, nwrite);
}

static void vty_backward_pure_word (struct _vty *vty)
{
  while (vty->cp > 0 && vty->buf[vty->cp - 1] != ' ')
    vty_backward_char (vty);
}

void vector_only_index_free (void *index)
{
  free ( index);
}

static void vty_complete_command (struct _vty *vty)
{
  int i;
  int ret;
  char **matched = NULL;
  vector vline;

  vline = cmd_make_strvec (vty->buf);
  if (vline == NULL)
    return;

  /* In case of 'help \t'. */
  if (isspace ((int) vty->buf[vty->length - 1]))
    vector_set (vline, NULL);

  matched = cmd_complete_command_lib (vline, vty, &ret, 1);
  
  cmd_free_strvec (vline);

  vty_out (vty, "%s", VTY_NEWLINE);
  switch (ret)
    {
    case CMD_ERR_AMBIGUOUS:
      vty_out (vty, "%% Ambiguous command.%s", VTY_NEWLINE);
      vty_prompt (vty);
      vty_redraw_line (vty);
      break;
    case CMD_ERR_NO_MATCH:
      /* vty_out (vty, "%% There is no matched command.%s", VTY_NEWLINE); */
      vty_prompt (vty);
      vty_redraw_line (vty);
      break;
    case CMD_COMPLETE_FULL_MATCH:
      vty_prompt (vty);
      vty_redraw_line (vty);
      vty_backward_pure_word (vty);
      vty_insert_word_overwrite (vty, matched[0]);
      vty_self_insert (vty, ' ');
      free ( matched[0]);
      break;
    case CMD_COMPLETE_MATCH:
      vty_prompt (vty);
      vty_redraw_line (vty);
      vty_backward_pure_word (vty);
      vty_insert_word_overwrite (vty, matched[0]);
      free (matched[0]);
      vector_only_index_free (matched);
      return;
      break;
    case CMD_COMPLETE_LIST_MATCH:
      for (i = 0; matched[i] != NULL; i++)
	{
	  if (i != 0 && ((i % 6) == 0))
	    vty_out (vty, "%s", VTY_NEWLINE);
	  vty_out (vty, "%-10s ", matched[i]);
	  free (matched[i]);
	}
      vty_out (vty, "%s", VTY_NEWLINE);

      vty_prompt (vty);
      vty_redraw_line (vty);
      break;
    case CMD_ERR_NOTHING_TODO:
      vty_prompt (vty);
      vty_redraw_line (vty);
      break;
    default:
      break;
    }
  if (matched)
    vector_only_index_free (matched);
}

static int cmd_describe_cmp(const void *a, const void *b)
{
  const struct cmd_token *first = *(struct cmd_token * const *)a;
  const struct cmd_token *second = *(struct cmd_token * const *)b;

  return strcmp(first->cmd, second->cmd);
}

static void cmd_describe_sort(vector matchvec)
{
  qsort(matchvec->index, vector_active(matchvec),
        sizeof(void*), cmd_describe_cmp);
}

void vector_unset (vector v, unsigned int i)
{
  if (i >= v->alloced)
    return;

  v->index[i] = NULL;

  if (i + 1 == v->active) 
    {
      v->active--;
      while (i && v->index[--i] == NULL && v->active--) 
	;				/* Is this ugly ? */
    }
}

static int desc_unique_string (vector v, const char *str)
{
  unsigned int i;
  struct cmd_token *token;

  for (i = 0; i < vector_active (v); i++)
    if ((token = vector_slot (v, i)) != NULL)
      if (strcmp (token->cmd, str) == 0)
	return 0;
  return 1;
}

static const char * cmd_entry_function_desc (const char *src, struct cmd_token *token)
{
  const char *dst = token->cmd;

  switch (token->terminal)
    {
      case TERMINAL_VARARG:
        return dst;

      case TERMINAL_RANGE:
        if (cmd_range_match (dst, src))
          return dst;
        else
          return NULL;

      case TERMINAL_IPV6:
        if (cmd_ipv6_match (src))
          return dst;
        else
          return NULL;

      case TERMINAL_IPV6_PREFIX:
        if (cmd_ipv6_prefix_match (src))
          return dst;
        else
          return NULL;

      case TERMINAL_IPV4:
        if (cmd_ipv4_match (src))
          return dst;
        else
          return NULL;

      case TERMINAL_IPV4_PREFIX:
        if (cmd_ipv4_prefix_match (src))
          return dst;
        else
          return NULL;

      /* Optional or variable commands always match on '?' */
      case TERMINAL_OPTION:
      case TERMINAL_VARIABLE:
        return dst;

      case TERMINAL_LITERAL:
        /* In case of 'command \t', given src is NULL string. */
        if (src == NULL)
          return dst;

        if (strncmp (src, dst, strlen (src)) == 0)
          return dst;
        else
          return NULL;

      default:
        return NULL;
    }
}

static vector cmd_describe_command_real (vector vline, struct _vty *vty, int *status)
{
  unsigned int i;
  vector cmd_vector;
#define INIT_MATCHVEC_SIZE 10
  vector matchvec;
  struct cmd_element *cmd_element;
  unsigned int index;
  int ret;
  enum match_type match;
  char *command;
  vector matches = NULL;
  vector match_vector;
  uint32_t command_found = 0;
  const char *last_word;

  /* Set index. */
  if (vector_active (vline) == 0)
    {
      *status = CMD_ERR_NO_MATCH;
      return NULL;
    }

  index = vector_active (vline) - 1;

  /* Make copy vector of current node's command vector. */
  cmd_vector = vector_copy (cmd_node_vector (cmdvec, vty->node));

  /* Prepare match vector */
  matchvec = vector_init ();

  /* Filter commands and build a list how they could possibly continue. */
  for (i = 0; i <= index; i++)
    {
      command = vector_slot (vline, i);

      if (matches)
	cmd_matches_free(&matches);

      ret = cmd_vector_filter(cmd_vector,
	                      FILTER_RELAXED,
	                      vline, i,
	                      &match,
	                      &matches);

      if (ret != CMD_SUCCESS)
	{
	  vector_free (cmd_vector);
	  vector_free (matchvec);
	  cmd_matches_free(&matches);
	  *status = ret;
	  return NULL;
	}

      /* The last match may well be ambigious, so break here */
      if (i == index)
	break;

      if (match == vararg_match)
	{
	  /* We found a vararg match - so we can throw out the current matches here
	   * and don't need to continue checking the command input */
	  unsigned int j, k;

	  for (j = 0; j < vector_active (matches); j++)
	    if ((match_vector = vector_slot (matches, j)) != NULL)
	      for (k = 0; k < vector_active (match_vector); k++)
	        {
	          struct cmd_token *token = vector_slot (match_vector, k);
	          vector_set (matchvec, token);
	        }

	  *status = CMD_SUCCESS;
	  vector_set(matchvec, &token_cr);
	  vector_free (cmd_vector);
	  cmd_matches_free(&matches);
	  cmd_describe_sort(matchvec);
	  return matchvec;
	}

      ret = is_cmd_ambiguous(cmd_vector, command, matches, match);
      if (ret == 1)
	{
	  vector_free (cmd_vector);
	  vector_free (matchvec);
	  cmd_matches_free(&matches);
	  *status = CMD_ERR_AMBIGUOUS;
	  return NULL;
	}
      else if (ret == 2)
	{
	  vector_free (cmd_vector);
	  vector_free (matchvec);
	  cmd_matches_free(&matches);
	  *status = CMD_ERR_NO_MATCH;
	  return NULL;
	}
    }

  /* Make description vector. */
  for (i = 0; i < vector_active (matches); i++)
    {
      if ((cmd_element = vector_slot (cmd_vector, i)) != NULL)
	{
	  unsigned int j;
	  vector vline_trimmed;

	  command_found++;
	  last_word = vector_slot(vline, vector_active(vline) - 1);
	  if (last_word == NULL || !strlen(last_word))
	    {
	      vline_trimmed = vector_copy(vline);
	      vector_unset(vline_trimmed, vector_active(vline_trimmed) - 1);

	      if (cmd_is_complete(cmd_element, vline_trimmed)
		  && desc_unique_string(matchvec, command_cr))
		{
		  if (match != vararg_match)
		    vector_set(matchvec, &token_cr);
		}

	      vector_free(vline_trimmed);
	    }

	  match_vector = vector_slot (matches, i);
	  if (match_vector)
	    {
	      for (j = 0; j < vector_active(match_vector); j++)
		{
		  struct cmd_token *token = vector_slot(match_vector, j);
		  const char *string;

		  string = cmd_entry_function_desc(command, token);
		  if (string && desc_unique_string(matchvec, string))
		    vector_set(matchvec, token);
		}
	    }
	}
    }

  /*
   * We can get into this situation when the command is complete
   * but the last part of the command is an optional piece of
   * the cli.
   */
  last_word = vector_slot(vline, vector_active(vline) - 1);
  if (command_found == 0 && (last_word == NULL || !strlen(last_word)))
    vector_set(matchvec, &token_cr);

  vector_free (cmd_vector);
  cmd_matches_free(&matches);

  if (vector_slot (matchvec, 0) == NULL)
    {
      vector_free (matchvec);
      *status = CMD_ERR_NO_MATCH;
      return NULL;
    }

  *status = CMD_SUCCESS;
  cmd_describe_sort(matchvec);
  return matchvec;
}

static void vty_describe_fold (struct _vty *vty, int cmd_width,
		   unsigned int desc_width, struct cmd_token *token)
{
  char *buf;
  const char *cmd, *p;
  int pos;

  cmd = token->cmd[0] == '.' ? token->cmd + 1 : token->cmd;

  if (desc_width <= 0)
    {
      vty_out (vty, "  %-*s  %s%s", cmd_width, cmd, token->desc, VTY_NEWLINE);
      return;
    }

  buf = calloc (1, strlen (token->desc) + 1);

  for (p = token->desc; strlen (p) > desc_width; p += pos + 1)
    {
      for (pos = desc_width; pos > 0; pos--)
      if (*(p + pos) == ' ')
        break;

      if (pos == 0)
      break;

      strncpy (buf, p, pos);
      buf[pos] = '\0';
      vty_out (vty, "  %-*s  %s%s", cmd_width, cmd, buf, VTY_NEWLINE);

      cmd = "";
    }

  vty_out (vty, "  %-*s  %s%s", cmd_width, cmd, p, VTY_NEWLINE);

  free (buf);
}

vector cmd_describe_command (vector vline, struct _vty *vty, int *status)
{
  vector ret;

  unsigned int onode;
  vector shifted_vline;
  unsigned int index;
	if ( cmd_try_do_shortcut(vty->node, vector_slot(vline, 0) ) ) {
		  onode = vty->node;
		  /* We can try it on enable node, cos' the vty is authenticated */

		  shifted_vline = vector_init ();
		  /* use memcpy? */
		  for (index = 1; index < vector_active (vline); index++) 
		{
		  vector_set_index (shifted_vline, index-1, vector_lookup(vline, index));
		}

		  ret = cmd_describe_command_real (shifted_vline, vty, status);

		  vector_free(shifted_vline);
		  vty->node = onode;
		  return ret;
	}

	return cmd_describe_command_real (vline, vty, status);
}

static void vty_describe_command (struct _vty *vty)
{
  int ret;
  vector vline;
  vector describe;
  unsigned int i, width, desc_width;
  struct cmd_token *token, *token_cr = NULL;

  vline = cmd_make_strvec (vty->buf);

  /* In case of '> ?'. */
  if (vline == NULL)
    {
      vline = vector_init ();
      vector_set (vline, NULL);
    }
  else 
    if (isspace ((int) vty->buf[vty->length - 1]))
      vector_set (vline, NULL);

  describe = cmd_describe_command (vline, vty, &ret);

  vty_out (vty, "%s", VTY_NEWLINE);

  /* Ambiguous error. */
  switch (ret)
    {
    case CMD_ERR_AMBIGUOUS:
      vty_out (vty, "%% Ambiguous command.%s", VTY_NEWLINE);
      goto out;
      break;
    case CMD_ERR_NO_MATCH:
      vty_out (vty, "%% There is no matched command.%s", VTY_NEWLINE);
      goto out;
      break;
    }  

  /* Get width of command string. */
  width = 0;
  for (i = 0; i < vector_active (describe); i++)
    if ((token = vector_slot (describe, i)) != NULL)
      {
	unsigned int len;

	if (token->cmd[0] == '\0')
	  continue;

	len = strlen (token->cmd);
	if (token->cmd[0] == '.')
	  len--;

	if (width < len)
	  width = len;
      }

  /* Get width of description string. */
  desc_width = vty->width - (width + 6);

  /* Print out description. */
  for (i = 0; i < vector_active (describe); i++)
    if ((token = vector_slot (describe, i)) != NULL)
      {
	if (token->cmd[0] == '\0')
	  continue;
	
	if (strcmp (token->cmd, command_cr) == 0)
	  {
	    token_cr = token;
	    continue;
	  }

	if (!token->desc)
	  vty_out (vty, "  %-s%s",
		   token->cmd[0] == '.' ? token->cmd + 1 : token->cmd,
		   VTY_NEWLINE);
	else if (desc_width >= strlen (token->desc))
	  vty_out (vty, "  %-*s  %s%s", width,
		   token->cmd[0] == '.' ? token->cmd + 1 : token->cmd,
		   token->desc, VTY_NEWLINE);
	else
	  vty_describe_fold (vty, width, desc_width, token);

      }

  if ((token = token_cr))
    {
      if (!token->desc)
	vty_out (vty, "  %-s%s",
		 token->cmd[0] == '.' ? token->cmd + 1 : token->cmd,
		 VTY_NEWLINE);
      else if (desc_width >= strlen (token->desc))
	vty_out (vty, "  %-*s  %s%s", width,
		 token->cmd[0] == '.' ? token->cmd + 1 : token->cmd,
		 token->desc, VTY_NEWLINE);
      else
	vty_describe_fold (vty, width, desc_width, token);
    }

out:
  cmd_free_strvec (vline);
  if (describe)
    vector_free (describe);

  vty_prompt (vty);
  vty_redraw_line (vty);
}

int vty_read (struct _vty *vty, unsigned char *buf,int nbytes)
{
	int i ;

	for (i = 0; i < nbytes; i++) 
		{
		  if (buf[i] == IAC)
		{
		  if (!vty->iac)
			{
			  vty->iac = 1;
			  continue;
			}
		  else
			{
			  vty->iac = 0;
			}
		}
		  
		  if (vty->iac_sb_in_progress && !vty->iac)
		{
			if (vty->sb_len < sizeof(vty->sb_buf))
			  vty->sb_buf[vty->sb_len] = buf[i];
			vty->sb_len++;
			continue;
		}

		  if (vty->iac)
		{
		  /* In case of telnet command */
		  int ret = 0;
		  ret = vty_telnet_option (vty, buf + i, nbytes - i);
		  vty->iac = 0;
		  i += ret;
		  continue;
		}
				

		  if (vty->status == VTY_MORE)
		{
		  switch (buf[i])
			{
			case CONTROL('C'):
			case 'q':
			case 'Q':
				vty_prompt (vty);
			  break;
			default:
			  break;
			}
		  continue;
		}

		  /* Escape character. */
		  if (vty->escape == VTY_ESCAPE)
		{
		  vty_escape_map (buf[i], vty);
		  continue;
		}
		  
		  if (vty->escape == VTY_LITERAL)
			{
			  vty_self_insert (vty, buf[i]);
			  vty->escape = VTY_NORMAL;
			  continue;
			}
		  
		  /* Pre-escape status. */
		  if (vty->escape == VTY_PRE_ESCAPE)
		{
		  switch (buf[i])
			{
			case '[':
			  vty->escape = VTY_ESCAPE;
			  break;
			case 'b':
			  vty_backward_word (vty);
			  vty->escape = VTY_NORMAL;
			  break;
			case 'f':
			  vty_forward_word (vty);
			  vty->escape = VTY_NORMAL;
			  break;
			case 'd':
			  vty_forward_kill_word (vty);
			  vty->escape = VTY_NORMAL;
			  break;
			case CONTROL('H'):
			case 0x7f:
			  vty_backward_kill_word (vty);
			  vty->escape = VTY_NORMAL;
			  break;
			default:
			  vty->escape = VTY_NORMAL;
			  break;
			}
		  continue;
		}

		  switch (buf[i])
		{
		case CONTROL('A'):
		  vty_beginning_of_line (vty);
		  break;
		case CONTROL('B'):
		  vty_backward_char (vty);
		  break;
		case CONTROL('C'):
		  //vty_stop_input (vty);
		  break;
		case CONTROL('D'):
		  vty_delete_char (vty);
		  break;
		case CONTROL('E'):
		  vty_end_of_line (vty);
		  break;
		case CONTROL('F'):
		  vty_forward_char (vty);
		  break;
		case CONTROL('H'):
		case 0x7f:
		  vty_delete_backward_char (vty);
		  break;
		case CONTROL('K'):
		  vty_kill_line (vty);
		  break;
		case CONTROL('N'):
		  vty_next_line (vty);
		  break;
		case CONTROL('P'):
		  vty_previous_line (vty);
		  break;
		case CONTROL('T'):
		  vty_transpose_chars (vty);
		  break;
		case CONTROL('U'):
		  vty_kill_line_from_beginning (vty);
		  break;
			case CONTROL('V'):
			  vty->escape = VTY_LITERAL;
			  break;
		case CONTROL('W'):
		  vty_backward_kill_word (vty);
		  break;
		case CONTROL('Z'):
		  //vty_end_config (vty);
		  break;
		case '\n':
		case '\r':
		  vty_out (vty, "%s", VTY_NEWLINE);
		  vty_execute (vty);
		  break;
		case '\t':
		  vty_complete_command (vty);
		  break;
		case '?':
			vty_describe_command (vty);
		  break;
		case '\033':
		  if (i + 1 < nbytes && buf[i + 1] == '[')
			{
			  vty->escape = VTY_ESCAPE;
			  i++;
			}
		  else
			vty->escape = VTY_PRE_ESCAPE;
		  break;
		default:
		  if (buf[i] > 31 && buf[i] < 127)
			vty_self_insert (vty, buf[i]);
		  break;
		}
		}

	return 0;
}

struct _vty *vty_create (int vty_sock, unsigned int node_type, char *hostname)
{
  struct _vty *vty;


  /* Allocate new vty structure and set up default values. */
  vty = vty_new_init (vty_sock, node_type);
  snprintf(vty->hostname, sizeof(vty->hostname), "%s", hostname);
  return vty;
}

void vty_list(struct _vty *vty)
{
	unsigned int i;
	struct cmd_node *cnode = vector_slot (cmdvec, vty->node);
	struct cmd_element *cmd;

	for (i = 0; i < vector_active (cnode->cmd_vector); i++)
		if ((cmd = vector_slot (cnode->cmd_vector, i)) != NULL
				&& !(cmd->attr == CMD_ATTR_DEPRECATED
				|| cmd->attr == CMD_ATTR_HIDDEN))
				vty_out (vty, "  %s%s", cmd->string,VTY_NEWLINE);

	return;
}

void vty_free (struct _vty *vty)
{
	int i =0;

	if (!vty)
		return;

	for (i = 0; i < VTY_HIST_CMD_SIZE; i++) {
		if (vty->hist[i])
			free(vty->hist[i]);
	}

	return;
}



