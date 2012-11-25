CC=clang
#CC=gcc
EXEC=drssl
CUSTOMSSL=-I/usr/local/ssl/include -L/usr/local/ssl/lib

CFLAGS=-O -Wall -Wuninitialized -Wbad-function-cast -Wcast-align -Wcast-qual -Wchar-subscripts -Winline -Wmissing-prototypes -Wnested-externs -Wpointer-arith -Wredundant-decls -Wshadow -Wstrict-prototypes -Wpointer-arith -Wno-long-long
LFLAGS=-lssl -lcrypto
SRCS=drssl.c


all:
	$(CC) -o $(EXEC) $(CFLAGS) $(SRCS) $(CUSTOMSSL) $(LFLAGS)


