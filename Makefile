CC = gcc
TARGET = netutil

CFLAGS = -c -Wall -I. -g
LDFLAGS = -lpcap

OBJECTS = 	src/main.o \
			src/netutil.o \
			src/scanner.o

all : $(TARGET)

$(TARGET) : $(OBJECTS)
	$(CC) $(OBJECTS) -o $@ $(LDFLAGS) 

src/%.o : src/%.c
	$(CC) $(CFLAGS) -o $@ $< 

clean :
	rm -rf src/*.o $(TARGET)