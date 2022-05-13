#include "common.h"

int client(const char *server_ip, int port, const char *cmd, const char *arg)
{
	struct addrinfo hints, *res;
	int err;
	data dsend;
	int sock;
	struct sockaddr_in s_server;
	char buffer[BUFFSIZE];
	unsigned int len;
	int received = 0;

	dbg("server_ip=%s\n", server_ip);
	dbg("cmd=%s\n", cmd);
	dbg("arg=%s\n", arg);

	if (strncmp(cmd, CMD_BAN, sizeof(CMD_BAN)) == 0) {
		/* check if the ban_ip ip address is real */
		memset(&hints, 0, sizeof(hints));
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_family = AF_INET;

		if ((err = getaddrinfo(arg, NULL, &hints, &res)) != 0) {
			fprintf(stderr, "invalid ban IP `%s'\n", arg);
			exit(1);
		}

		dbg("ban_ip: %s\n",
		    inet_ntoa(((struct sockaddr_in *)
			       (res->ai_addr))->sin_addr));
		freeaddrinfo(res);
	}

	memset(&dsend, 0, sizeof(dsend));
	if (arg)
		strncpy(dsend.arg, arg, sizeof(dsend.arg) - 1);
	strncpy(dsend.cmd, cmd, sizeof(dsend.cmd) - 1);

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

	len = sizeof(data);
	if (send(sock, &dsend, len, 0) != len)
		die("Mismatch in number of sent bytes");

	dbg("Received: ");
	while (received < len) {
		int bytes = 0;
		data *drecv;

		if ((bytes = recv(sock, buffer, BUFFSIZE-1, 0)) < 1 &&
		    errno == 0) {
			printf("done\n");
			exit(0);
		}
		if (bytes < 0)
			die("Failed to receive bytes from server");

		received += bytes;
		buffer[bytes] = '\0';
		drecv = (data*)buffer;
		(void)drecv;
		dbg("%s", drecv->arg);
	}
	dbg("\n");
	close(sock);
	exit(0);
}
