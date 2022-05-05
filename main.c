#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>

#include "common.h"

static void usage(const char *prgname)
{
	printf("%s [-l] [-h HOST] [-p PORT] [-c COMMAND] [-a ARGUMENT]\n"
	       "\n"

	       "  -l launches the server\n"
	       "  -h host to connect to from the client\n"
	       "  -p port to listen on/connect to\n"
	       "  -c command (ban|exit)\n"
	       "  -a arg (ip address, exit status code)\n"
	       "  -w IP (white listed IP)\n"
	       " server eg.: ./ban_ip -l -p 7777\n"
	       " client eg.: ./ban_ip -h localhost -p 7777 -c ban -a 1.1.1.1\n",
	       prgname);
}

int main(int argc, char *argv[])
{
	int opt;
	char *host = NULL;
	int ret = 0, port = 0;
	char *cmd = NULL, *arg = NULL;
#define flag_h 1
#define flag_p 1 << 1
#define flag_c 1 << 2
#define flag_a 1 << 3
#define flag_s 1 << 4

	int flags = 0;
	int server_flags = flag_p | flag_s;
	int client_flags = flag_h | flag_p | flag_c | flag_a;

	while ((opt = getopt(argc, argv, "lh:p:c:a:w:")) != -1) {
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
			flags |= flag_a;
			arg = optarg;
			break;
		case 'w':
			if (flags & flag_s)
				wlist_add(optarg);
			break;

		default:
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (flags != server_flags && flags != client_flags) {
		fprintf(stderr, "Expected arguments\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (flags & flag_s) {
#ifndef DEBUG
		int pid = fork();

		if (pid < 0)
			fprintf(stderr, "can't fork");
		else if (pid) {
			wlist_wipe();
			return 0;
		}
#endif
		ret = server(port);
	}
	else
		ret = client(host, port, cmd, arg);
	wlist_wipe();
	return ret;
}
