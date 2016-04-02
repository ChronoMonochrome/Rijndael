#CC=i586-mingw32msvc-gcc
#CC=gcc#
#CXX=i586-mingw32msvc-g++#

#UNIX=1

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



CPPFLAGS=-Wall -Wno-write-strings -Wno-parentheses \
	-Werror=implicit-function-declaration \
	-I./include \
	-fno-strict-aliasing \
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
LDFLAGS=

else
CPPFLAGS+=-march=sandybridge
LDFLAGS=
endif

LDFLAGS+=-Wl,-no-undefined --enable-runtime-pseudo-reloc -L. -L./lib

DLL_SRCS=aes.cpp hugeint.cpp rsa.cpp base64.cpp lkm.cpp
SRCS=main.cpp file.cpp

OBJS=$(subst .cpp,.o,$(SRCS))

DLL_OBJS=$(subst .cpp,.o,$(DLL_SRCS))

BUFFERSIZE = 16777216
CPPLAGS += -DBUFFERSIZE=$(BUFFERSIZE)

all: crypto_hybrid$(EXT) libcrypto_hybrid.dll

libcrypto_hybrid.dll: $(DLL_OBJS)
	$(CXX) -shared -o libcrypto_hybrid.dll -Wl,--whole-archive $(CPPFLAGS) $(DLL_OBJS) $(LDFLAGS) -Wl,--no-whole-archive

crypto_hybrid$(EXT): $(OBJS) libcrypto_hybrid.dll
	$(CXX)  -o crypto_hybrid$(EXT) $(CPPFLAGS) $(OBJS) $(LDFLAGS) $(LDLIBS) libcrypto_hybrid.dll libcrypto.dll

depend: .depend

.depend: $(SRCS)
	rm -f ./.depend
	$(CXX) $(CFLAGS) -MM $^>>./.depend;

objclean:
	$(RM) $(OBJS)

clean: objclean
	$(RM) .depend *.o crypto_hybrid$(EXT) libcrypto_hybrid.dll decrypted.txt encrypted.txt

remake: clean all

include .depend
