#CC=i586-mingw32msvc-gcc
#CC=gcc#
#CXX=i586-mingw32msvc-g++#

UNIX=1

ifeq ($(UNIX), 1)
CXX=g++
EXT=
else
CXX=./cxx.sh
EXT=.exe
endif

RM=rm -f

GRAPHITE_FLAGS= \
    -floop-flatten \
    -floop-parallelize-all \
    -ftree-loop-linear \
    -floop-interchange \
    -floop-strip-mine \
    -floop-block


LTO_FLAGS=-flto=jobserver \
	-fno-fat-lto-objects \
	-fuse-linker-plugin \
	-D__LTO__ \
	-funit-at-a-time \
	-flto-report



CPPFLAGS=-Wall \
	-Werror=implicit-function-declaration \
	-I./include \
	-O2 \
	-ffast-math \
	-funsafe-loop-optimizations \
	-fgcse-after-reload \
	-ftree-partial-pre \
	-frename-registers \
        -fomit-frame-pointer \
	-pipe \
        -std=gnu++14


ifneq ($(UNIX), 1)
CPPFLAGS+=-DWIN -march=atom
LDFLAGS=-static 
LDLIBS=./lib/libssl.a ./lib/libcrypto.a ./lib/libgdi32.a
else
CPPFLAGS+=-march=sandybridge
LDLIBS=-lssl -lcrypto
endif

#-Wl,-flto
#-lssl -lcrypto  -Wl,-flto
SRCS=main.cpp aes.cpp hugeint.cpp rsa.cpp file.cpp base64.cpp
OBJS=$(subst .cpp,.o,$(SRCS))

BUFFERSIZE = 16777216
CPPLAGS += -DBUFFERSIZE=$(BUFFERSIZE)

all: crypto_hybrid$(EXT)

crypto_hybrid$(EXT): $(OBJS)
	$(CXX) -o crypto_hybrid$(EXT) $(CPPFLAGS) $(OBJS) $(LDFLAGS) $(LDLIBS) 

depend: .depend

.depend: $(SRCS)
	rm -f ./.depend
	$(CXX) $(CFLAGS) -MM $^>>./.depend;

objclean:
	$(RM) $(OBJS)

clean: objclean
	$(RM) .depend *.o crypto_hybrid$(EXT) decrypted.txt encrypted.txt

remake: clean all

include .depend
