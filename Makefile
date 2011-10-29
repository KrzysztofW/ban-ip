CC=gcc -m32
CFLAGS=-c -Wall -O3
LDFLAGS=
SOURCES=main.c client.c server.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=ban_ip

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(EXECUTABLE) $(OBJECTS) *~