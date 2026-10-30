CFLAGS ?= -O2 -Wall -Wextra -Werror
PREFIX ?= /usr/local

chimera-clock-scale: chimera-clock-scale.c
	$(CC) $(CFLAGS) -I$(PREFIX)/include -o $@ $< -L$(PREFIX)/lib -Wl,-rpath,$(PREFIX)/lib -lxenctrl -lxenguest

install: chimera-clock-scale
	install -m 0755 chimera-clock-scale $(PREFIX)/sbin/chimera-clock-scale

clean:
	rm -f chimera-clock-scale
