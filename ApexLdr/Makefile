NAME := ApexLdr
CCX64 := x86_64-w64-mingw32-gcc
PY := python3
DIST := dist
SRC := src
CFLAGS := -s -w -static -fpermissive -Wl,--subsystem,console -Iinclude -lkernel32 -luser32

all:
	@ $(CCX64) -o $(DIST)/$(NAME).dll $(SRC)/*.c $(CFLAGS) -Wl,--entry="DllMain" -masm=intel -shared -nostdlib
clean:
	@ rm -rf $(DIST)/*
