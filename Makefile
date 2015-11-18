CC=gcc
CXX=g++
RM=rm -f
CFLAGS=-Wall -Wno-pointer-sign -Wno-unused-variable -Werror=implicit-function-declaration
LDFLAGS=-lssl -lcrypto
SRCS=main.c rsa.c aes.c
OBJS=$(subst .c,.o,$(SRCS))

all: myAES

myAES: $(OBJS)
	$(CC) -o myAES $(OBJS) $(LDFLAGS) $(LDLIBS) 

depend: .depend

.depend: $(SRCS)
	rm -f ./.depend
	$(CC) $(CFLAGS) -MM $^>>./.depend;

objclean:
	$(RM) $(OBJS)

clean: objclean
	$(RM) .depend *.o myAES decrypted.txt encrypted.txt

include .depend
