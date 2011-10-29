#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>

#include "common.h"

/* display usage */
static void
usage(const char *prgname)
{
	printf("%s [-l] [-h HOST] [-p PORT] [-c COMMAND] [-a ARGUMENT]\n"
	       "\n"

	       "  -l launches the server\n"
	       "  -h host to connect to from the client\n"
	       "  -p port to listen on/connect to\n"
	       "  -c command\n"
	       "  -a arg\n",
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


        while ((opt = getopt(argc, argv, "lh:p:c:a:")) != -1) {
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

		default: /* '?' */
			usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (flags != server_flags && flags != client_flags) {
		//if (optind < 2) {
		printf("flags=%X server_flags=%X client_flags=%X\n", flags, server_flags, client_flags);
		printf("flag_h=%X ", flag_h);
		printf("flag_p=%X ", flag_p);
		printf("flag_c=%X ", flag_c);
		printf("flag_a=%X ", flag_a);
		printf("flag_s=%X ", flag_s);

		fprintf(stderr, "Expected arguments\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (flags & flag_s)
		ret = server(port);
	else
		ret = client(host, port, cmd, arg);

	return ret;
}
