#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netdb.h>
extern int h_errno;


typedef struct {
  char addr[15];
  char cmd[3];
} data;

#define MAXPENDING 5    /* Max connection requests */
#define BUFFSIZE   32

static inline void die(char *str) { perror(str); exit(1); }
static inline void wrn(char *str) { perror(str); }

int server(int);
int client(char*, int, char*, char*);

/* commands */
#define CMD_BAN "ban"

#ifdef DEBUG
#define dbg(fmt,...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#define dbg(fmt,...)
#endif

#define IPT_DROP_IN "iptables -I INPUT 5 -s %s -j DROP"
