CC=gcc
CFLAGS=-c -Wall -O3
LDFLAGS=-lpthread
SOURCES=main.c client.c server.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=ban_ip

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(EXECUTABLE) $(OBJECTS) *~

install:
	cp ban_ip /usr/local/bin/
	cp ban_ip.service /etc/systemd/system/
	systemctl enable ban_ip
	systemctl start ban_ip
uninstall:
	systemctl disable ban_ip
	systemctl stop ban_ip
	rm -f /usr/local/bin/ban_ip /etc/systemd/system/ban_ip.service
