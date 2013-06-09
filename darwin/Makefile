CC = clang
CFLAGS = -g -O2 -I. -I../libev -DVERSION="\"1.2\"" -DDARWIN_LAUNCHD -DDARWIN_MAC
LDFLAGS = -framework Foundation -framework SystemConfiguration -L. -lcrypto
DEPS = shadowd.h config.h ../src/local.h ../src/utils.h ../libev/ev.h
CSRC = ../src/local.c ../src/encrypt.c ../src/utils.c ../libev/ev.c
MSRC = shadowd.m
OBJECTS = $(CSRC:.c=.o) $(MSRC:.m=.o)
EXECUTABLE = shadowd

all: $(CSRC) $(MSRC) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.m $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJECTS) $(EXECUTABLE)
