CC=gcc
CFLAGS=-c -Wall -O3
LDFLAGS=-lpthread -lnetfilter_queue
STATIC_LIB=$(shell find /usr/lib -name libconfig.a 2> /dev/null)
SOURCES=main.c client.c server.c
OBJECTS=$(SOURCES:.c=.o)
EXE=ban-ip

all: $(SOURCES) $(EXE)

$(EXE): $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS) $(STATIC_LIB)

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(EXE) $(OBJECTS) *~

install:
	cp $(EXE) /usr/bin/
	cp ban-ip.service /etc/systemd/system/
	cp ban-ip.cfg /etc/
	systemctl enable ban-ip
	systemctl start ban-ip
uninstall:
	systemctl disable ban-ip
	systemctl stop ban-ip
	rm -f /usr/bin/ban-ip /etc/systemd/system/ban-ip.service /etc/ban-ip.cfg
