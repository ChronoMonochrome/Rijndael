CC=i586-mingw32msvc-gcc
#CC=gcc
CXX=i586-mingw32msvc-g++
RM=rm -f
CPPFLAGS=-Wall -Werror=implicit-function-declaration -O2 -ffast-math -funsafe-loop-optimizations -fno-permissive -I./include
CXXFLAGS=-Wall -Werror=implicit-function-declaration -O2 -ffast-math -funsafe-loop-optimizations -fno-permissive -I./include
LDLIBS=./lib/libssl.a ./lib/libcrypto.a ./lib/libgdi32.a
LDFLAGS=
SRCS=main.cpp aes.cpp hugeint.cpp rsa.cpp file.cpp
OBJS=$(subst .cpp,.o,$(SRCS))

all: myAES.exe

myAES.exe: $(OBJS)
	$(CXX) -o myAES.exe $(CPPFLAGS) $(OBJS) $(LDFLAGS) $(LDLIBS) 

depend: .depend

.depend: $(SRCS)
	rm -f ./.depend
	$(CXX) $(CFLAGS) -MM $^>>./.depend;

objclean:
	$(RM) $(OBJS)

clean: objclean
	$(RM) .depend *.o myAES decrypted.txt encrypted.txt

include .depend
