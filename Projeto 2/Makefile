.PHONY: all clean
all: server user

CFLAGS = -Wall -Wextra -Werror
AUXFILES = types.h constants.h sope.h

server: server.o log.o 
	@$(CC) -lpthread -pthread -pedantic -o server log.o  server.o 
#-D_REENTRANT

user: user.o log.o
	@$(CC) $(CFLAGS) -pedantic -o user user.o log.o 

log.o: log.c $(AUXFILES)
	@$(CC) $(CFLAGS) -pedantic -c log.c

server.o: server.c server.h
	@$(CC) $(CFLAGS) -pedantic -c server.c

user.o: user.c user.h
	@$(CC) $(CFLAGS) -pedantic -c user.c


clean:
	@rm -f server user log *.o
	