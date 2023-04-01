CC = gcc
CFLAGS = -Wall
TARGET = test
SOURCES = leptjson.c test.c

all: $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET)

clean:
	rm -f $(TARGET)
