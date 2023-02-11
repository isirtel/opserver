#include <arpa/telnet.h>

char *ptelnet_will_echo(void)
{
	static char cmd[] = { IAC, WILL, TELOPT_ECHO, '\0' };
	return cmd;
}

char *ptelnet_will_suppress_go_ahead (void)
{
	static char cmd[] = { IAC, WILL, TELOPT_SGA, '\0' };
	return cmd;
}

char * ptelnet_dont_linemode (void)
{
	static char cmd[] = { IAC, DONT, TELOPT_LINEMODE, '\0' };
	return cmd;
}

char * ptelnet_do_window_size (void)
{
	static char cmd[] = { IAC, DO, TELOPT_NAWS, '\0' };
	return cmd;
}

