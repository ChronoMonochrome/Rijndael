#CC=i586-mingw32msvc-gcc
#CC=gcc#
#CXX=i586-mingw32msvc-g++#
CXX=./cxx.sh
#CXX=g++
RM=rm -f
LTO_FLAGS=-flto=jobserver \
	-fno-fat-lto-objects \
	-fuse-linker-plugin \
	-D__LTO__ \
	-funit-at-a-time \
	-flto-report

CPPFLAGS=-Wall \
	-Werror=implicit-function-declaration \
	-march=native \
	-O2 \
	-ffast-math \
	-funsafe-loop-optimizations \
	-fgcse-after-reload \
	-ftree-partial-pre \
	-frename-registers \
        -fomit-frame-pointer \
	-pipe \
	-mhard-float \
        -std=gnu++14 \
	-I./include


#LDLIBS=./lib/libssl.a ./lib/libcrypto.a ./lib/libgdi32.a
LDFLAGS=-static
#-Wl,-flto
#-lssl -lcrypto  -Wl,-flto
SRCS=main.cpp
# aes.cpp hugeint.cpp rsa.cpp file.cpp base64.cpp
OBJS=$(subst .cpp,.o,$(SRCS))

BUFFERSIZE = 16777216
CPPLAGS += -DBUFFERSIZE=$(BUFFERSIZE)

all: crypto_hybrid.exe

crypto_hybrid.exe: $(OBJS)
	$(CXX) -o crypto_hybrid.exe $(CPPFLAGS) $(OBJS) $(LDFLAGS) $(LDLIBS) 

depend: .depend

.depend: $(SRCS)
	rm -f ./.depend
	$(CXX) $(CFLAGS) -MM $^>>./.depend;

objclean:
	$(RM) $(OBJS)

clean: objclean
	$(RM) .depend *.o crypto_hybrid.exe decrypted.txt encrypted.txt

remake: clean all

include .depend
