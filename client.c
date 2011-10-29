#include "common.h"

int client(char *server_ip, int port, char *cmd, char *ban_ip)
{
	struct addrinfo hints, *res;
	int err;
	data *dsend, *drecv;
	int sock;
	struct sockaddr_in s_server;
	char buffer[BUFFSIZE];
	unsigned int len;
	int received = 0;

	dbg("server_ip=%s\n", server_ip);
	dbg("cmd=%s\n", cmd);
	dbg("ban_ip=%s\n", ban_ip);

	/* check if the ban_ip ip address is real */
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;

	if ((err = getaddrinfo(ban_ip, NULL, &hints, &res)) != 0)
		die("Getaddrinfo of ban_ip failed");

	dbg("ban_ip address : %s\n",
	    inet_ntoa(((struct sockaddr_in *)(res->ai_addr))->sin_addr));

	freeaddrinfo(res);


	dsend = malloc(sizeof(data));
	strncpy(dsend->addr, ban_ip, sizeof(dsend->addr));
	strncpy(dsend->cmd, cmd, sizeof(dsend->cmd));

	/* Create the TCP socket */
	if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		die("Failed to create socket");


	/* Construct the server sockaddr_in structure */
	memset(&s_server, 0, sizeof(s_server));         /* Clear struct */
	s_server.sin_family = AF_INET;                  /* Internet/IP */


	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;

	if ((err = getaddrinfo(server_ip, NULL, &hints, &res)) != 0)
		die("Getaddrinfo failed");

	s_server.sin_addr.s_addr =
		((struct sockaddr_in *)(res->ai_addr))->sin_addr.s_addr;

	dbg("ip address : %s\n", inet_ntoa(s_server.sin_addr));

	freeaddrinfo(res);

	s_server.sin_port = htons(port);

	/* Establish connection */
	if (connect(sock,
		    (struct sockaddr *) &s_server,
		    sizeof(s_server)) < 0) {
		die("Failed to connect with server");
	}

	/* Send the word to the server */
	len = sizeof(data);
	if (send(sock, dsend, len, 0) != len)
		die("Mismatch in number of sent bytes");

	/* Receive the word back from the server */
	dbg("Received: ");
	while (received < len) {
		int bytes = 0;

		if ((bytes = recv(sock, buffer, BUFFSIZE-1, 0)) < 1)
			die("Failed to receive bytes from server");

		received += bytes;
		buffer[bytes] = '\0';        /* Assure null terminated string */
		drecv = (data*)buffer;
		dbg("%s", drecv->addr);
	}
	dbg("\n");
	close(sock);
	exit(0);
}
