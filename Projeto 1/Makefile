.PHONY: all clean
all: forensic

CFLAGS = -Wall -Wextra -Werror

forensic: proj.c forensic.h
	@gcc $(CFLAGS) -pedantic proj.c -o forensic

clean:
	@rm -f forensic
	