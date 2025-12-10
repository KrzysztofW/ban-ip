#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>

typedef struct {
	char arg[16];
	char cmd[10];
} data;

#define MAXPENDING 5
#define BUFFSIZE   32

static inline void die(char *str) { perror(str); exit(1); }
static inline void wrn(char *str) { perror(str); }

int server(int, const char *bind_addr);
int client(const char*, int, const char*, const char*);
int wlist_add(const char *);
void wlist_wipe(void);
void plist_wipe(void);
void bind_antiscan_port(void);
void plist_add(uint16_t port);
void plist_wipe(void);
void fdlist_wipe(void);
void threadlist_wipe(void);
void iptables_cleanup(void);
int iptables_init(void);

/* commands */
#define CMD_BAN "ban"
#define CMD_EXIT "exit"
#define CMD_PURGE "purge"

static inline void list_commands(void)
{
	printf(CMD_BAN" <IP>\n");
	printf(CMD_EXIT" <code>\n");
	printf(CMD_PURGE"\n");
}

#ifdef DEBUG
#define dbg(fmt,...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#define dbg(fmt,...)
#endif

#define IPT_BAN "/sbin/iptables -I ban-ip -s %s -j DROP"

#define IPT_FLUSH "/sbin/iptables -F ban-ip"
#define IPT_REMOVE_FROM_FORWARD "/sbin/iptables -D FORWARD -j ban-ip"
#define IPT_REMOVE_FROM_INPUT "/sbin/iptables -D INPUT -j ban-ip"
#define IPT_DELETE "/sbin/iptables -X ban-ip"
#define IPT_CREATE "/sbin/iptables -N ban-ip"
#define IPT_ADD_TO_FORWARD "/sbin/iptables -I FORWARD -j ban-ip"
#define IPT_ADD_TO_INPUT "/sbin/iptables -I INPUT -j ban-ip"
#define IPT_NFQUEUE "/sbin/iptables -I ban-ip -p tcp --dport %d --syn -j NFQUEUE --queue-num %d"
