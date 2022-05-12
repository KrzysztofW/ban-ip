#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <libconfig.h>
#include "common.h"

static int port = 0;
static int flag_fork = 1;
static const char *host = NULL;
static const char *cmd = NULL;
static const char *arg = NULL;
static const char *bind_addr = "127.0.0.1";

#define flag_h 1
#define flag_p 1 << 1
#define flag_c 1 << 2
#define flag_s 1 << 3

static void usage(const char *prgname)
{
	printf("%s [-l] [-h HOST] [-p PORT] [-c COMMAND] [-a ARGUMENT]\n"
	       "\n"

	       "  -l launches the server\n"
	       "  -h host to connect to from the client\n"
	       "  -p port to listen on/connect to\n"
	       "  -b bind address (only server - default localhost)\n"
	       "  -c command (ban|exit)\n"
	       "  -a arg (ip address, exit status code)\n"
	       "  -w IP (white listed IP)\n"
	       "  -s port (port number)\n"
	       "  -d do not fork\n"
	       "  -f config file\n"
	       " server eg.: ./ban_ip -l -p 7777\n"
	       " client eg.: ./ban_ip -h localhost -p 7777 -c ban -a 1.1.1.1\n"
	       "             ./ban_ip -h localhost -p 7777 -c exit -a 1\n"
	       "\n"
	       " ban port scanners eg.:\n"
	       " ./ban_ip -l -p 7777 -s 445 -s 23\n",
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

static int read_config(const char *cfg_file)
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

	if (config_lookup_string(&cfg, "ip_whitelist", &str)) {
		fill_whitelist(str);
	}
	if (config_lookup_string(&cfg, "trap_ports", &str)) {
		fill_trap_ports(str);
	}
	config_lookup_bool(&cfg, "fork", &flag_fork);

 end:
	config_destroy(&cfg);
	return ret == 0 ? flags : ret;
}

int main(int argc, char *argv[])
{
	int opt, ret;
	const char *cfg_file = NULL;
	int flags = 0;
	int server_flags = flag_p | flag_s;
	int client_flags = flag_h | flag_p | flag_c;

	while ((opt = getopt(argc, argv, "lh:p:c:a:w:s:db:f:")) != -1) {
		switch (opt) {
		case 'l':
			flags |= flag_s;
			break;
		case 'h':
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

		default:
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (cfg_file)
		flags = read_config(cfg_file);

	if (flags != server_flags && flags != client_flags) {
		fprintf(stderr, "Expected arguments\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

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
		bind_antiscan_port();
		ret = server(port, bind_addr);
	}
	else
		ret = client(host, port, cmd, arg);
	wlist_wipe();
	threadlist_wipe();
	return ret;
}
