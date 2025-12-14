#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <signal.h>
#include <syslog.h>
#include <libconfig.h>
#include "common.h"

static int port;
static int flag_fork = 1;
static const char *host;
static const char *cmd;
static const char *arg;
static char *bind_addr = "127.0.0.1";
static uint8_t bind_addr_alloc;
static const char *cfg_file;
const char *prog_name = "ban-ip";
uint8_t ipt_forward_chain;
uint8_t ipt_input_chain;
int nfqueue_nb = -1;

#define flag_h 1
#define flag_p 1 << 1
#define flag_c 1 << 2
#define flag_s 1 << 3

static void usage(const char *prgname)
{
	printf("%s [-l] [-H HOST] [-p PORT] [-c COMMAND] [-a ARGUMENT]\n"
	       "\n"

	       "  -h shows this help\n"
	       "  -l launches the server\n"
	       "  -H host to connect to from the client\n"
	       "  -p port to listen on/connect to\n"
	       "  -b bind address (only server - default localhost)\n"
	       "  -c command (ban|exit)\n"
	       "  -a arg (ip address, exit status code)\n"
	       "  -w IP (white listed IP)\n"
	       "  -s port (port number)\n"
	       "  -n nfqueue number (use nfqueue instead of socket binding)\n"
	       "  -d do not fork\n"
	       "  -f config file\n"
	       "  -L list commands\n"
	       " server eg.: ./ban-ip -l -p 7777\n"
	       " client eg.: ./ban-ip -H localhost -p 7777 -c ban -a 1.1.1.1\n"
	       "             ./ban-ip -H localhost -p 7777 -c exit -a 1\n"
	       "\n"
	       " ban port scanners eg.:\n"
	       " ./ban-ip -l -p 7777 -s 445 -s 23\n",
	       prgname);
}

static int fill_whitelist(const char *list)
{
	while (list[0]) {
		char item[16];
		int n = 0;

		while (list[0] != ' ' && list[0] != '\0') {
			if (n > sizeof(item))
				return -1;
			item[n++] = list[0];
			list++;
		}
		item[n] = '\0';
		wlist_add(item);
		if (list[0] != '\0')
			list++;
	}
	return 0;
}

static int fill_trap_ports(const char *list)
{
	while (list[0]) {
		char item[16];
		int n = 0;

		while (list[0] != ' ' && list[0] != '\0') {
			if (n > sizeof(item))
				return -1;
			item[n++] = list[0];
			list++;
		}
		item[n] = '\0';
		plist_add(atoi(item));
		if (list[0] != '\0')
			list++;
	}
	return 0;
}

static int load_cfg(config_t *cfg, const char *filename)
{
    config_init(cfg);

    if (!config_read_file(cfg, filename)) {
	    fprintf(stderr, "%s:%d - %s\n", config_error_file(cfg),
		    config_error_line(cfg), config_error_text(cfg));
	    config_destroy(cfg);
	    return -1;
    }
    return 0;
}

static int set_ipt_chains(const char *list)
{
	while (list[0]) {
		char item[8];
		int n = 0;

		while (list[0] != ' ' && list[0] != '\0') {
			if (n > sizeof(item))
				return -1;
			item[n++] = list[0];
			list++;
		}
		item[n] = '\0';
		if (strncmp(item, "FORWARD", sizeof(item)) == 0) {
			ipt_forward_chain = 1;
		} else if (strncmp(item, "INPUT", sizeof(item)) == 0) {
			ipt_input_chain = 1;
		} else {
			fprintf(stderr, "invalid iptables chain `%s'\n", item);
			openlog(prog_name, 0, LOG_USER);
			syslog(LOG_NOTICE, "invalid iptables chain `%s'", item);
			closelog();
		}
		if (list[0] != '\0')
			list++;
	}
	return 0;
}

static int read_config(void)
{
	int flags = flag_s, ret = 0;
	config_t cfg;
	const char *str = NULL;

	if (load_cfg(&cfg, cfg_file) < 0)
		return -1;

	if (!config_lookup_int(&cfg, "listen_port", &port)) {
		fprintf(stderr,
			"invalid or missing mandatory listen_port option\n");
		ret = -1;
		goto end;
	}
	flags |= flag_p;

	if (config_lookup_string(&cfg, "bind_address", &str)) {
		bind_addr = strdup(str);
		bind_addr_alloc = 1;
	}
	if (config_lookup_string(&cfg, "ip_whitelist", &str)) {
		fill_whitelist(str);
	}
	if (config_lookup_string(&cfg, "trap_ports", &str)) {
		fill_trap_ports(str);
	}
	if (config_lookup_string(&cfg, "iptables_chains", &str)) {
		set_ipt_chains(str);
		if (ipt_forward_chain == 0 && ipt_input_chain == 0)
			ipt_input_chain = 1;
	}
	config_lookup_bool(&cfg, "fork", &flag_fork);
	config_lookup_int(&cfg, "nfqueue_number", &nfqueue_nb);
 end:
	config_destroy(&cfg);
	return ret == 0 ? flags : ret;
}

static void sig_handler(int sig)
{
	wlist_wipe();
	fdlist_wipe();
	threadlist_wipe();
	if (bind_addr_alloc)
		free(bind_addr);
	iptables_cleanup();
	exit(EXIT_SUCCESS);
}

void reload_cfg(void)
{
	if (cfg_file == NULL)
		return;

	iptables_init();
	openlog(prog_name, 0, LOG_USER);
	syslog(LOG_NOTICE, "reloading configuration");
	closelog();
	fdlist_wipe();
	threadlist_wipe();
	wlist_wipe();
	free(bind_addr);
	read_config();
	bind_antiscan_port();
}

static void sig_usr_handler(int sig)
{
	reload_cfg();
}

int main(int argc, char *argv[])
{
	int opt, ret;
	int flags = 0;
	int server_flags = flag_p | flag_s;
	int client_flags = flag_h | flag_p | flag_c;

	while ((opt = getopt(argc, argv, "lhH:p:c:a:w:s:db:f:Ln:")) != -1) {
		switch (opt) {
		case 'l':
			flags |= flag_s;
			break;
		case 'H':
			host = optarg;
			flags |= flag_h;
			break;
		case 'p':
			flags |= flag_p;
			port = atoi(optarg);
			break;
		case 'c':
			flags |= flag_c;
			cmd = optarg;
			break;
		case 'a':
			arg = optarg;
			break;
		case 'w':
			if (flags & flag_s)
				wlist_add(optarg);
			break;
		case 's':
			if (flags & flag_s)
				plist_add(atoi(optarg));
			break;
		case 'd':
			flag_fork = 0;
			break;
		case 'b':
			bind_addr = optarg;
			break;
		case 'f':
			cfg_file = optarg;
			break;
		case 'n':
			nfqueue_nb = atoi(optarg);
			break;
		case 'L':
			list_commands();
			exit(EXIT_SUCCESS);

		default:
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	/* cleanup eventually broken iptables configuration */
	iptables_cleanup();

	if (cfg_file)
		flags = read_config();
	else
		ipt_input_chain = 1;

	if (flags != server_flags && flags != client_flags) {
		fprintf(stderr, "Expected arguments\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	signal(SIGTERM, &sig_handler);
	signal(SIGINT, &sig_handler);
	signal(SIGUSR1, &sig_usr_handler);

	if (flags & flag_s) {
		if (flag_fork) {
			int pid = fork();

			if (pid < 0)
				fprintf(stderr, "can't fork");
			else if (pid) {
				wlist_wipe();
				plist_wipe();
				return 0;
			}
		}
		if (iptables_init() < 0) {
			iptables_cleanup();
			die("failed to initialize iptables");
		}
		bind_antiscan_port();
		ret = server(port, bind_addr);
		if (bind_addr_alloc)
			free(bind_addr);
		iptables_cleanup();
	} else
		ret = client(host, port, cmd, arg);
	wlist_wipe();
	threadlist_wipe();
	return ret;
}
