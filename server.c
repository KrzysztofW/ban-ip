#include <syslog.h>
#include <pthread.h>
#include "common.h"
#include "list.h"

const char *prog_name = "ban-ip";

typedef struct whitelist_entry {
	char ip[16];
	list_t list;
} whitelist_entry_t;
LIST_HEAD(wlist);

typedef struct threadlist_entry {
	pthread_t thread;
	list_t list;
} threadlist_entry_t;
LIST_HEAD(thlist);

typedef struct portlist_entry {
	uint16_t port;
	list_t list;
} portlist_entry_t;
LIST_HEAD(plist);

int wlist_add(const char *ip)
{
	whitelist_entry_t *entry = malloc(sizeof(whitelist_entry_t));

	if (entry == NULL)
		return -1;
	dbg("white listing IP: %s\n", ip);
	strncpy(entry->ip, ip, sizeof(entry->ip) - 1);
	list_add_tail(&entry->list, &wlist);
	return 0;
}

static uint8_t wlist_ispresent(const char *ip)
{
	whitelist_entry_t *e;

	LIST_FOR_EACH_ENTRY(e, &wlist, list)
		if (strncmp(e->ip, ip, sizeof(e->ip)) == 0)
			return 1;
	return 0;
}

void wlist_wipe(void)
{
	whitelist_entry_t *e, *n;

	LIST_FOR_EACH_ENTRY_SAFE(e, n, &wlist, list) {
		list_del(&e->list);
		free(e);
	}
}

static pthread_t *threadlist_add(void)
{
	threadlist_entry_t *entry = malloc(sizeof(threadlist_entry_t));

	if (entry == NULL)
		return NULL;
	list_add_tail(&entry->list, &thlist);
	return &entry->thread;
}

void threadlist_wipe(void)
{
	threadlist_entry_t *e, *n;

	LIST_FOR_EACH_ENTRY_SAFE(e, n, &thlist, list) {
		pthread_cancel(e->thread);
		pthread_join(e->thread, NULL);
		list_del(&e->list);
		free(e);
	}
}

void plist_add(uint16_t port)
{
	portlist_entry_t *entry = malloc(sizeof(portlist_entry_t));

	if (entry == NULL)
		return;
	entry->port = port;
	list_add_tail(&entry->list, &plist);
}

void plist_wipe(void)
{
	portlist_entry_t *e, *n;

	LIST_FOR_EACH_ENTRY_SAFE(e, n, &plist, list) {
		list_del(&e->list);
		free(e);
	}
}

static uint16_t get_port_from_socket(int fd)
{
	struct sockaddr_in sin;
	socklen_t len = sizeof(sin);

	if (getsockname(fd, (struct sockaddr *)&sin, &len) < 0)
		return 0;
	return ntohs(sin.sin_port);
}

static void *antiscan_th_cb(void *arg)
{
	int serversock = (uintptr_t)arg;

	while (1) {
		int clientsock;
		struct sockaddr_in s_client;
		unsigned int clientlen = sizeof(s_client);
		char ipt_str[1024];

		if ((clientsock =
		     accept(serversock, (struct sockaddr *) &s_client,
			    &clientlen)) < 0) {
			wrn("Failed to accept client connection");
			continue;
		}

		openlog(prog_name, 0, LOG_USER);
		if (wlist_ispresent(inet_ntoa(s_client.sin_addr))) {
			syslog(LOG_NOTICE,
			       "antiscan caught on port %u -> %s white-listed",
			       get_port_from_socket(serversock),
			       inet_ntoa(s_client.sin_addr));
			closelog();
			close(clientsock);
			continue;
		}
		syslog(LOG_NOTICE, "antiscan caught on port %u -> ban IP %s",
		       get_port_from_socket(serversock),
		       inet_ntoa(s_client.sin_addr));
		closelog();

		sprintf(ipt_str, IPT_BAN, inet_ntoa(s_client.sin_addr));
		dbg("antiscan: %s", ipt_str);
		if (system(ipt_str) < 0)
			wrn("antiscan: fork failed %m\n");
		close(clientsock);
	}
	return NULL;}

static int __bind_antiscan_port(uint16_t port)
{
	pthread_t *th;
	int serversock;
	struct sockaddr_in s_server;
	int true = 1;

	if ((serversock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		fprintf(stderr, "Failed to create socket");
		return -1;
	}

	memset(&s_server, 0, sizeof(s_server));
	s_server.sin_family = AF_INET;
	s_server.sin_addr.s_addr = htonl(INADDR_ANY);
	s_server.sin_port = htons(port);

	if (setsockopt(serversock, SOL_SOCKET, SO_REUSEADDR,
		       &true, sizeof(int)) < 0) {
		fprintf(stderr, "Setsockopt");
		return -1;
	}

	if (bind(serversock, (struct sockaddr *) &s_server,
		 sizeof(s_server)) < 0) {
		fprintf(stderr, "antiscan: failed to bind on port: %u\n", port);
		close(serversock);
		return -1;
	}

	if (listen(serversock, MAXPENDING) < 0)
		die("Failed to listen on server socket");

	if ((th = threadlist_add()) == NULL)
		return -1;

	openlog(prog_name, 0, LOG_USER);
	syslog(LOG_NOTICE, "antiscan: listening on port %u", port);
	closelog();

	return pthread_create(th, NULL, antiscan_th_cb,
			      (void *)(uintptr_t)serversock);
}

void bind_antiscan_port(void)
{
	portlist_entry_t *e, *tmp;

	LIST_FOR_EACH_ENTRY_SAFE(e, tmp, &plist, list) {
		__bind_antiscan_port(e->port);
		list_del(&e->list);
		free(e);
	}
}

static void handle_client(int sock)
{
	int received = -1;
	data drecv;
	char ipt_str[1024];

	if ((received = recv(sock, &drecv, sizeof(data), 0)) < 0)
		wrn("Failed to receive initial bytes from client");

	while (received > 0) {
		dbg("drecv->cmd=%s, drecv->arg=%s\n", drecv.cmd, drecv.arg);

		if (strncmp(drecv.cmd, CMD_BAN, strlen(CMD_BAN)) == 0) {
			sprintf(ipt_str, IPT_BAN, drecv.arg);

			dbg("%s\n", ipt_str);
			openlog(prog_name, 0, LOG_USER);
			if (wlist_ispresent(drecv.arg))
				syslog(LOG_NOTICE, "%s white-listed",
				       drecv.arg);
			else {
				syslog(LOG_NOTICE, "permanently banned %s",
				       drecv.arg);
				if (system(ipt_str) < 0)
					wrn("fork failed\n");
			}
			closelog();

		} else if (strncmp(drecv.cmd, CMD_EXIT,
				   strlen(CMD_EXIT)) == 0) {
			dbg("exiting\n");
			openlog(prog_name, 0, LOG_USER);
			syslog(LOG_NOTICE, "exiting");
			closelog();
			close(sock);
			wlist_wipe();
			threadlist_wipe();
			exit(atoi(drecv.arg));
		} else {
			wrn("invalid command\n");
			break;
		}

		if (send(sock, &drecv, received, 0) != received) {
			wrn("Failed to send bytes to client");
		}

		if ((received = recv(sock, &drecv, sizeof(data), 0)) < 0) {
			wrn("Failed to receive additional bytes from client");
		}
	}
	close(sock);
}

int server(int port, const char *bind_addr)
{
	int serversock, clientsock;
	struct sockaddr_in s_server, s_client;
	int true = 1;

	if ((serversock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		fprintf(stderr, "Failed to create socket");
		return -1;
	}

	memset(&s_server, 0, sizeof(s_server));
	s_server.sin_family = AF_INET;
	s_server.sin_addr.s_addr = inet_addr(bind_addr);
	s_server.sin_port = htons(port);

	if (setsockopt(serversock, SOL_SOCKET, SO_REUSEADDR,
		       &true, sizeof(int)) < 0) {
		fprintf(stderr, "Setsockopt");
		return -1;
	}

	if (bind(serversock, (struct sockaddr *) &s_server,
		 sizeof(s_server)) < 0) {
		fprintf(stderr, "Failed to bind the server socket");
		return -1;
	}

	if (listen(serversock, MAXPENDING) < 0)
		die("Failed to listen on server socket");

	if (system(IPT_FLUSH) < 0 || system(IPT_REMOVE) < 0 ||
	    system(IPT_DELETE) < 0 || system(IPT_CREATE) ||
	    system(IPT_ADD) < 0)
		die("failed to initialize iptables");

	openlog(prog_name, 0, LOG_USER);
	syslog(LOG_NOTICE, "started");
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
