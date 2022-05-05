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
