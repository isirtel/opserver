#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <pthread.h>

#include "base/oplog.h"
#include "opbox/parser.h"
#include "opbox/utils.h"
#include "timer_service.h"
#include "iniparser.h"
#include "config.h"

#define MAXLINES       65535
#define _TIMER_SERVICE_CRON "timer_service:path"

#define SENDMAIL       "sendmail"

#define SENDMAIL_ARGS  "-ti"

enum {
	LOGMODE_NONE = 0,
	LOGMODE_STDIO = (1 << 0),
	LOGMODE_SYSLOG = (1 << 1),
	LOGMODE_BOTH = LOGMODE_SYSLOG + LOGMODE_STDIO,
};

#define START_ME_NORMAL -1

typedef struct CronFile {
	struct CronFile *cf_next;
	struct CronLine *cf_lines;
	char *cf_username;
	char cf_wants_starting;
	char cf_has_running;
	char cf_deleted;
} CronFile;

typedef struct CronLine {
	struct CronLine *cl_next;
	char *cl_cmd;                   /* shell command */
	pid_t cl_pid;                   /* >0:running, <0:needs to be started in this minute, 0:dormant */
	char * cl_mailto;
	unsigned int cl_empty_mail_size;
	char *cl_shell;
	/* ordered by size, not in natural order. makes code smaller: */
	char cl_Dow[7];                 /* 0-6, beginning sunday */
	char cl_Mons[12];               /* 0-11 */
	char cl_Hrs[24];                /* 0-23 */
	char cl_Days[32];               /* 1-31 */
	char cl_Mins[60];               /* 0-59 */
} CronLine;

struct _timer_thread_ 
{
	pthread_t thread_id;
	pthread_attr_t thread_attr;
};

struct timer_globals {
	time_t crontab_dir_mtime;
	char crontab_dir_name[128];
	CronFile *cron_files;
	char *default_shell;
};

struct _timer_struct {
	struct timer_globals g;
	struct _timer_thread_ thread;
	int run;
	int rescan;
};

static struct _timer_struct * self = NULL;


static const char DowAry[] =
	"sun""mon""tue""wed""thu""fri""sat"
;

static const char MonAry[] =
	"jan""feb""mar""apr""may""jun""jul""aug""sep""oct""nov""dec"
;

static void ParseField(char *user, char *ary, int modvalue, int off, const char *names, char *ptr)
{
	char *base = ptr;
	int n1 = -1;
	int n2 = -1;
	int skip = 0;
	char *endp;
	int i;

	while (1) {

		skip = 0;
		if (*ptr == '*') {
			n1 = 0;  /* everything will be filled */
			n2 = modvalue - 1;
			skip = 1;
			++ptr;
		} else if (isdigit(*ptr)) {
			
			if (n1 < 0) {
				n1 = strtol(ptr, &endp, 10) + off;
			} else {
				n2 = strtol(ptr, &endp, 10) + off;
			}
			ptr = endp; /* gcc likes temp var for &endp */
			skip = 1;
		} else if (names) {
			for (i = 0; names[i]; i += 3) {
				/* was using strncmp before... */
				if (strncasecmp(ptr, &names[i], 3) == 0) {
					ptr += 3;
					if (n1 < 0) {
						n1 = i / 3;
					} else {
						n2 = i / 3;
					}
					skip = 1;
					break;
				}
			}
		}

		/* handle optional range '-' */
		if (skip == 0) {
			goto err;
		}
		if (*ptr == '-' && n2 < 0) {
			++ptr;
			continue;
		}

		/*
		 * collapse single-value ranges, handle skipmark, and fill
		 * in the character array appropriately.
		 */
		if (n2 < 0) {
			n2 = n1;
		}
		if (*ptr == '/') {
			char *endp;
			skip = strtol(ptr + 1, &endp, 10);
			ptr = endp; /* gcc likes temp var for &endp */
		}

		/*
		 * fill array, using a failsafe is the easiest way to prevent
		 * an endless loop
		 */
		{
			int s0 = 1;
			int failsafe = 1024;

			--n1;
			do {
				n1 = (n1 + 1) % modvalue;

				if (--s0 == 0) {
					ary[n1 % modvalue] = 1;
					s0 = skip;
				}
				if (--failsafe == 0) {
					goto err;
				}
			} while (n1 != n2);
		}
		if (*ptr != ',') {
			break;
		}
		++ptr;
		n1 = -1;
		n2 = -1;
	}

	if (*ptr) {
 err:
		log_warn("user %s: parse error at %s\n", user, base);
		return;
	}
}

static void FixDayDow(CronLine *line)
{
	unsigned i;
	int weekUsed = 0;
	int daysUsed = 0;

	for (i = 0; i < ARRAY_SIZE(line->cl_Dow); ++i) {
		if (line->cl_Dow[i] == 0) {
			weekUsed = 1;
			break;
		}
	}
	for (i = 0; i < ARRAY_SIZE(line->cl_Days); ++i) {
		if (line->cl_Days[i] == 0) {
			daysUsed = 1;
			break;
		}
	}
	if (weekUsed != daysUsed) {
		if (weekUsed)
			memset(line->cl_Days, 0, sizeof(line->cl_Days));
		else /* daysUsed */
			memset(line->cl_Dow, 0, sizeof(line->cl_Dow));
	}
}


static void delete_cronfile(const char *userName)
{
	struct _timer_struct *service = self;
	log_debug("delete cronfile\n");
	CronFile **pfile = &service->g.cron_files;
	CronFile *file;
	CronLine **pline;
	CronLine *line;
	while ((file = *pfile) != NULL) {
		if (strcmp(userName, file->cf_username) == 0) {
			pline = &file->cf_lines;
			file->cf_has_running = 0;
			file->cf_deleted = 1;

			while ((line = *pline) != NULL) {
				if (line->cl_pid > 0) {
					file->cf_has_running = 1;
					pline = &line->cl_next;
				} else {
					*pline = line->cl_next;
					free(line->cl_cmd);
					free(line);
				}
			}
			if (file->cf_has_running == 0) {
				*pfile = file->cf_next;
				free(file->cf_username);
				free(file);
				continue;
			}
		}
		pfile = &file->cf_next;
	}
}

char* is_prefixed_with(const char *string, const char *key)
{
	while (*key != '\0') {
		if (*key != *string)
			return NULL;
		key++;
		string++;
	}
	return (char*)string;
}

static void load_crontab(const char *fileName)
{
	struct _timer_struct *service = self;
	struct parser_t *parser;
	struct stat sbuf;
	int maxLines;
	char *tokens[6];
	CronFile *file;
	CronLine **pline;
	CronLine *line;
	int n;
	char *et;
	int ret = 0;
	char *mailTo = NULL;
	char *shell = NULL;
	typedef struct SpecialEntry {
		const char *name;
		const char tokens[8];
	} SpecialEntry;

	const SpecialEntry *e;

	static const SpecialEntry SpecAry[] = {
		/*              hour  day   month weekday */
		{ "yearly",     "0\0" "1\0" "1\0" "*" },
		{ "annually",   "0\0" "1\0" "1\0" "*" },
		{ "monthly",    "0\0" "1\0" "*\0" "*" },
		{ "weekly",     "0\0" "*\0" "*\0" "0" },
		{ "daily",      "0\0" "*\0" "*\0" "*" },
		{ "midnight",   "0\0" "*\0" "*\0" "*" },
		{ "hourly",     "*\0" "*\0" "*\0" "*" },
		{ "reboot",     ""                    },
	};

	delete_cronfile(fileName);
	
	parser = config_open(fileName);
	if (!parser) {
		log_warn("config_open[%s]failed\n", fileName);
		return;
	}

	maxLines = MAXLINES;

	ret = fstat(fileno(parser->fp), &sbuf);

	log_debug("load_crontab[%s], fstat ret = %d\n", fileName, ret);

	if (!ret) {
		file = calloc(1, sizeof(CronFile));
		file->cf_username = strdup(fileName);
		pline = &file->cf_lines;

		while (1) {

			if (!--maxLines) {
				log_warn("user %s: too many lines\n", fileName);
				break;
			}

			n = config_read(parser, tokens, 6, 1, "# \t", PARSE_NORMAL | PARSE_KEEP_COPY);
			if (!n) {
				break;
			}

			log_debug("user:%s entry:%s\n", fileName, parser->data);

			/* check if line is setting MAILTO= */
			if (is_prefixed_with(tokens[0], "MAILTO=")) {
				free(mailTo);
				mailTo = (tokens[0][7]) ? strdup(&tokens[0][7]) : NULL;
				continue;
			}
			if (is_prefixed_with(tokens[0], "SHELL=")) {
				free(shell);
				shell = strdup(&tokens[0][6]);
				continue;
			}
			
			if (tokens[0][0] == '@') {
				/*
				 * "@daily /a/script/to/run PARAM1 PARAM2..."
				 */

				e = SpecAry;

				if (n < 2)
					continue;
				for (;;) {
					if (strcmp(e->name, tokens[0] + 1) == 0) {
						/*
						 * tokens[1] is only the first word of command,
						 * can'r use it.
						 * find the entire command in unmodified string:
						 */
						tokens[5] = skip_whitespace(skip_non_whitespace(skip_whitespace(parser->data)));
						if (e->tokens[0]) {
							et = (char*)e->tokens;
							/* minute is "0" for all specials */
							tokens[0] = (char*)"0";
							tokens[1] = et;
							tokens[2] = et + 2;
							tokens[3] = et + 4;
							tokens[4] = et + 6;
						}
						goto got_it;
					}
					if (!e->tokens[0])
						break;
					e++;
				}
				continue; /* bad line (unrecognized '@foo') */
			}
			/* check if a minimum of tokens is specified */
			if (n < 6)
				continue;

	got_it:
			*pline = line = calloc(1,sizeof(*line));
			if (tokens[0][0] == '@') { /* "@reboot" line */
				file->cf_wants_starting = 1;
				line->cl_pid = START_ME_NORMAL; /* wants to start */
				/* line->cl_Mins/Hrs/etc stay zero: never match any time */
			} else
			{
				/* parse date ranges */
				ParseField(file->cf_username, line->cl_Mins, 60, 0, NULL, tokens[0]);
				ParseField(file->cf_username, line->cl_Hrs, 24, 0, NULL, tokens[1]);
				ParseField(file->cf_username, line->cl_Days, 32, 0, NULL, tokens[2]);
				ParseField(file->cf_username, line->cl_Mons, 12, -1, MonAry, tokens[3]);
				ParseField(file->cf_username, line->cl_Dow, 7, 0, DowAry, tokens[4]);
				/*
				 * fix days and dow - if one is not "*" and the other
				 * is "*", the other is set to 0, and vise-versa
				 */
				FixDayDow(line);
			}
			/* copy mailto (can be NULL) */
			line->cl_mailto = mailTo?strdup(mailTo):NULL;
			line->cl_shell = shell?strdup(shell):NULL;
			/* copy command */
			line->cl_cmd = strdup(tokens[5]);
			
			log_debug("user:%s entry:%s,cmd=%s\n", fileName, parser->data, line->cl_cmd);
			pline = &line->cl_next;
//bb_error_msg("M[%s]F[%s][%s][%s][%s][%s][%s]", mailTo, tokens[0], tokens[1], tokens[2], tokens[3], tokens[4], tokens[5]);
		}
		*pline = NULL;

		file->cf_next = service->g.cron_files;
		service->g.cron_files = file;
	}

	config_close(parser);
	if (mailTo)
		free(mailTo);
	if (shell)
		free(shell);
}

static void rescan_crontab_dir(void)
{
	struct _timer_struct *service = self;
	struct dirent *den;
	DIR *dir;
	CronFile *file;
	char buf_path[496] = {};

again:
	for (file = service->g.cron_files; file; file = file->cf_next) {
		if (!file->cf_deleted) {
			delete_cronfile(file->cf_username);
			goto again;
		}
	}

	dir = opendir(service->g.crontab_dir_name);

	while ((den = readdir(dir)) != NULL) {
		if (strchr(den->d_name, '.') != NULL) {
			continue;
		}
		log_debug("try load %s\n", den->d_name);
		snprintf(buf_path, sizeof(buf_path), "%s/%s", service->g.crontab_dir_name, den->d_name);
		load_crontab(buf_path);
	}
	closedir(dir);
}

/*
 * process_finished_job - called when job terminates and when mail terminates
 */
static void process_finished_job(const char *user, CronLine *line)
{
	line->cl_pid = 0;
	return;
}

static pid_t start_one_job(const char *user, CronLine *line)
{
	struct _timer_struct *service = self;

	const char *shell;
	pid_t pid;


	/* Prepare things before vfork */
	shell = line->cl_shell ? line->cl_shell : service->g.default_shell;

	/* Fork as the user in question and run program */
	pid = vfork();
	if (pid == 0) {
		/* CHILD */
		/* initgroups, setgid, setuid, and chdir to home or CRON_DIR */
		log_debug("child running %s\n", shell);
		/* crond 3.0pl1-100 puts tasks in separate process groups */
		log_debug("exe %s\n", line->cl_cmd);
		execl(shell, shell, "-c", line->cl_cmd, (char *) NULL);
		log_warn("can't execute '%s' for user %s\n", shell, user);
	}
	if (pid < 0) {
		log_warn("vfork\n");
		pid = 0;
	}
	line->cl_pid = pid;
	return pid;
}

/*
 * Determine which jobs need to be run.  Under normal conditions, the
 * period is about a minute (one scan).  Worst case it will be one
 * hour (60 scans).
 */
static void flag_starting_jobs(time_t t1, time_t t2)
{
	time_t t;
	struct tm *ptm;
	CronFile *file;
	CronLine *line;
	struct _timer_struct *service = self;
	/* Find jobs > t1 and <= t2 */

	for (t = t1 - t1 % 60; t <= t2; t += 60) {


		if (t <= t1)
			continue;

		ptm = localtime(&t);
		for (file = service->g.cron_files; file; file = file->cf_next) {
			if (file->cf_deleted)
				continue;
			for (line = file->cf_lines; line; line = line->cl_next) {
				if (line->cl_Mins[ptm->tm_min]
				 && line->cl_Hrs[ptm->tm_hour]
				 && (line->cl_Days[ptm->tm_mday] || line->cl_Dow[ptm->tm_wday])
				 && line->cl_Mons[ptm->tm_mon]
				) {
					if (line->cl_pid > 0) {
					} else if (line->cl_pid == 0) {
						line->cl_pid = -1;
						file->cf_wants_starting = 1;
					}
				}
			}
		}
	}
}

static void start_jobs(int wants_start)
{
	CronFile *file;
	CronLine *line;
	struct _timer_struct *service = self;
	pid_t pid;

	for (file = service->g.cron_files; file; file = file->cf_next) {
		if (!file->cf_wants_starting)
			continue;

		file->cf_wants_starting = 0;
		for (line = file->cf_lines; line; line = line->cl_next) {
			if (line->cl_pid != wants_start)
				continue;

			pid = start_one_job(file->cf_username, line);
			log_debug("USER %s pid %d cmd %s\n",
				file->cf_username, (int)pid, line->cl_cmd);
			if (pid < 0) {
				file->cf_wants_starting = 1;
			}
			if (pid > 0) {
				file->cf_has_running = 1;
			}
		}
	}
}

/*
 * Check for job completion, return number of jobs still running after
 * all done.
 */
static int check_completions(void)
{
	CronFile *file;
	CronLine *line;
	int num_still_running = 0;
	struct _timer_struct *service = self;
	int r;

	for (file = service->g.cron_files; file; file = file->cf_next) {
		if (!file->cf_has_running)
			continue;

		file->cf_has_running = 0;
		for (line = file->cf_lines; line; line = line->cl_next) {

			if (line->cl_pid <= 0)
				continue;

			log_debug("wait pid %d\n", line->cl_pid);
			r = waitpid(line->cl_pid, NULL, WNOHANG);
			
			log_debug("wait pid %d over, ret=%d\n", line->cl_pid, r);
			if (r < 0 || r == line->cl_pid) {
				process_finished_job(file->cf_username, line);
				if (line->cl_pid == 0) {
					/* sendmail was not started for it */
					continue;
				}
				/* else: sendmail was started, job is still running, fall thru */
			}
			/* else: r == 0: "process is still running" */
			file->cf_has_running = 1;
		}
//FIXME: if !file->cf_has_running && file->deleted: delete it!
//otherwise deleted entries will stay forever, right?
		num_still_running += file->cf_has_running;
	}
	return num_still_running;
}

static void *timer_routine (void *arg)
{
	time_t t2;
	unsigned sleep_time;
	time_t t1;
	long dt;

	struct _timer_struct *service = (struct _timer_struct *)arg;

	t2 = time(NULL);
	sleep_time = 60;
	service->run = 1;
	
	log_debug("timer_routine run\n");
	while(service->run) {
		
			/* Synchronize to 1 minute, minimum 1 second */
		t1 = t2;
		sleep(sleep_time - (time(NULL) % sleep_time));
		t2 = time(NULL);
		dt = (long)t2 - (long)t1;

		if (service->rescan) {
			rescan_crontab_dir();
			service->rescan = 0;
		}

		if (dt < -60 * 60 || dt > 60 * 60) {
			log_warn ("time disparity of %ld minutes detected\n", dt / 60);
			/* and we do not run any jobs in this case */
		} else if (dt > 0) {
			/* Usual case: time advances forward, as expected */
			flag_starting_jobs(t1, t2);
			start_jobs(START_ME_NORMAL);
			sleep_time = 60;
			if (check_completions() > 0) {
				/* some jobs are still running */
				sleep_time = 10;
			}
		}
			/* else: time jumped back, do not run any jobs */
	} /* for (;;) */

	return NULL;
}

void *timer_service_init(void)
{
	log_debug("timer service init\n");
	struct _timer_struct *service = NULL;
	dictionary *dict;
	const char *str;
	service =  calloc(1, sizeof(*service));
	self = service;
	service->g.default_shell = strdup("/bin/bash");

	dict = iniparser_load(OPSERVER_CONF);
	if (!dict) {
		log_error ("iniparser_load faild[%s]\n", OPSERVER_CONF);
		goto exit;
	}

	if(!(str = iniparser_getstring(dict,_TIMER_SERVICE_CRON,NULL))) {
		log_error ("iniparser_getstring faild[%s]\n", _TIMER_SERVICE_CRON);
		goto exit;
	}

	op_strlcpy(service->g.crontab_dir_name, str, sizeof(service->g.crontab_dir_name));

	log_debug("dir_name:%s\n", service->g.crontab_dir_name);

	iniparser_freedict(dict);
	
	rescan_crontab_dir();

	if(pthread_attr_init(&service->thread.thread_attr)) {
		log_error ("opmgr pthread_attr_init faild\n");
		goto exit;
	}

	if(pthread_create(&service->thread.thread_id, &service->thread.thread_attr, timer_routine, service)) {
		log_error ("opmgr pthread_create faild\n");
		goto exit;
	}

	return service; /* not reached */
exit:
	timer_service_exit(service);
	return NULL;
}

void timer_service_exit(void *timer)
{
	return;
}

