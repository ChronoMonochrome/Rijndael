CC=gcc
CXX=g++
RM=rm -f
CFLAGS=-Wall -Werror=implicit-function-declaration -I./include
LDLIBS=./lib/libssl.a ./lib/libcrypto.a ./lib/libgdi32.a
LDFLAGS=
SRCS=main.c
OBJS=$(subst .c,.o,$(SRCS))

all: myAES.exe

myAES.exe: $(OBJS)
	$(CC) -o myAES.exe $(OBJS) $(LDFLAGS) $(LDLIBS) 

depend: .depend

.depend: $(SRCS)
	rm -f ./.depend
	$(CC) $(CFLAGS) -MM $^>>./.depend;

objclean:
	$(RM) $(OBJS)

clean: objclean
	$(RM) .depend *.o myAES decrypted.txt encrypted.txt

include .depend
