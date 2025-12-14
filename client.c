#include "common.h"

int client(const char *server_ip, int port, const char *cmd, const char *arg)
{
	struct addrinfo hints, *res;
	int err;
	int sock;
	struct sockaddr_in s_server;
	char buffer[1024];
	char *buf_pos = buffer;
	uint16_t len;

	dbg("server_ip=%s\n", server_ip);
	dbg("cmd=%s\n", cmd);
	dbg("arg=%s\n", arg);

	if (cmd == NULL) {
		fprintf(stderr, "empty command\n");
		exit(1);
	}

	if (strncmp(cmd, CMD_BAN, sizeof(CMD_BAN)) == 0) {
		/* check if the ban-ip ip address is real */
		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_family = AF_INET;

		if ((err = getaddrinfo(arg, NULL, &hints, &res)) != 0) {
			fprintf(stderr, "invalid ban IP `%s'\n", arg);
			exit(1);
		}

		dbg("ban-ip: %s\n",
		    inet_ntoa(((struct sockaddr_in *)
			       (res->ai_addr))->sin_addr));
		freeaddrinfo(res);
	}

	memset(buffer, 0, sizeof(buffer));
	len = strlen(cmd) + 1;

	if (arg)
		len += strlen(arg) + 1;

	len = htons(len);
	memcpy(buf_pos, (char *)&len, sizeof(len));
	len = ntohs(len);
	buf_pos += sizeof(len);
	buf_pos += snprintf(buf_pos, sizeof(buffer) - (buf_pos - buffer),
			    "%s", cmd) + 1;
	if (arg)
		buf_pos += snprintf(buf_pos,
				    sizeof(buffer) - (buf_pos - buffer),
				    "%s", arg) + 1;

	if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		die("Failed to create socket");

	memset(&s_server, 0, sizeof(s_server));
	s_server.sin_family = AF_INET;

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;

	if ((err = getaddrinfo(server_ip, NULL, &hints, &res)) != 0) {
		fprintf(stderr, "invalid server IP `%s': %m", server_ip);
		exit(1);
	}

	s_server.sin_addr.s_addr =
		((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;

	dbg("ip address : %s\n", inet_ntoa(s_server.sin_addr));

	freeaddrinfo(res);

	s_server.sin_port = htons(port);

	if (connect(sock, (struct sockaddr *) &s_server, sizeof(s_server)) < 0)
		die("Failed to connect with server");

	len += sizeof(len);
	if (send(sock, buffer, len, 0) != len)
		die("Mismatch in number of sent bytes");

	printf("done\n");
	close(sock);
	exit(0);
}
