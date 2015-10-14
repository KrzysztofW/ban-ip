#include "common.h"

void HandleClient(int sock)
{
	int received = -1;
	data *drecv = malloc(sizeof(data));
	char ipt_str[1024];

	/* Receive message */
	if ((received = recv(sock, drecv, sizeof(data), 0)) < 0) {
		wrn("Failed to receive initial bytes from client");
	}

	/* Send bytes and check for more incoming data in loop */
	while (received > 0) {
		/* Send back received data */
		dbg("drecv->cmd=%s, drecv->addr=%s\n",
		       drecv->cmd, drecv->addr);

		if (! strncmp(drecv->cmd, CMD_BAN, strlen(CMD_BAN))) {
			sprintf(ipt_str, IPT_DROP_IN, drecv->addr);
			printf("%s\n", ipt_str);
			if (system(ipt_str) < 0)
				wrn("fork failed\n");
		}

		if (send(sock, drecv, received, 0) != received) {
			wrn("Failed to send bytes to client");
		}

		/* Check for more data */
		if ((received = recv(sock, drecv, sizeof(data), 0)) < 0) {
			wrn("Failed to receive additional bytes from client");
		}
	}
	close(sock);
}

int server(int port)
{
	int serversock, clientsock;
	struct sockaddr_in s_server, s_client;
	int true = 1;

	/* Create the TCP socket */
	if ((serversock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		die("Failed to create socket");
	}

	/* Construct the server sockaddr_in structure */
	memset(&s_server, 0, sizeof(s_server));           /* Clear struct  */
	s_server.sin_family = AF_INET;                    /* Internet/IP   */
	s_server.sin_addr.s_addr = htonl(INADDR_ANY);     /* Incoming addr */
	s_server.sin_port = htons(port);                  /* server port   */

	if (setsockopt(serversock, SOL_SOCKET, SO_REUSEADDR,
		       &true, sizeof(int)) == -1)
		die("Setsockopt");


	/* Bind the server socket */
	if (bind(serversock, (struct sockaddr *) &s_server,
		 sizeof(s_server)) < 0) {
		die("Failed to bind the server socket");
	}

	/* Listen on the server socket */
	if (listen(serversock, MAXPENDING) < 0) {
		die("Failed to listen on server socket");
	}

	/* Run until cancelled */
	while (1) {
		unsigned int clientlen = sizeof(s_client);

		/* Wait for client connection */
		if ((clientsock =
		     accept(serversock, (struct sockaddr *) &s_client,
			    &clientlen)) < 0) {
			wrn("Failed to accept client connection");
		}
		/*    dbg(stdout, "Client connected: %s\n",
		      inet_ntoa(s_client.sin_addr)); */

		HandleClient(clientsock);
	}
	return 0;
}
