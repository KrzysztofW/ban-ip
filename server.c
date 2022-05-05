#include "common.h"
#include <syslog.h>

const char *prog_name = "ban-ip";

void handle_client(int sock)
{
	int received = -1;
	data *drecv = malloc(sizeof(data));
	char ipt_str[1024];

	if ((received = recv(sock, drecv, sizeof(data), 0)) < 0)
		wrn("Failed to receive initial bytes from client");

	while (received > 0) {
		dbg("drecv->cmd=%s, drecv->arg=%s\n",
		    drecv->cmd, drecv->arg);

		if (strncmp(drecv->cmd, CMD_BAN, strlen(CMD_BAN)) == 0) {
			sprintf(ipt_str, IPT_DROP_IN, drecv->arg);

			dbg("%s\n", ipt_str);
			openlog(prog_name, 0, LOG_USER);
			syslog(LOG_NOTICE, "permanently banned %s", drecv->arg);
			closelog();

			if (system(ipt_str) < 0)
				wrn("fork failed\n");
		} else if (strncmp(drecv->cmd, CMD_EXIT,
				   strlen(CMD_EXIT)) == 0) {
			dbg("exiting\n");
			openlog(prog_name, 0, LOG_USER);
			syslog(LOG_NOTICE, "exiting");
			closelog();
			close(sock);
			exit(atoi(drecv->arg));
		}

		if (send(sock, drecv, received, 0) != received) {
			wrn("Failed to send bytes to client");
		}

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

	if ((serversock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		die("Failed to create socket");

	memset(&s_server, 0, sizeof(s_server));
	s_server.sin_family = AF_INET;
	s_server.sin_addr.s_addr = htonl(INADDR_ANY);
	s_server.sin_port = htons(port);

	if (setsockopt(serversock, SOL_SOCKET, SO_REUSEADDR,
		       &true, sizeof(int)) < 0)
		die("Setsockopt");

	if (bind(serversock, (struct sockaddr *) &s_server,
		 sizeof(s_server)) < 0) {
		die("Failed to bind the server socket");
	}

	if (listen(serversock, MAXPENDING) < 0)
		die("Failed to listen on server socket");

	openlog(prog_name, 0, LOG_USER);
	syslog(LOG_NOTICE, "starting");
	closelog();

	while (1) {
		unsigned int clientlen = sizeof(s_client);

		if ((clientsock =
		     accept(serversock, (struct sockaddr *) &s_client,
			    &clientlen)) < 0) {
			wrn("Failed to accept client connection");
		}
		/*    dbg(stdout, "Client connected: %s\n",
		      inet_ntoa(s_client.sin_addr)); */

		handle_client(clientsock);
	}
	return 0;
}
