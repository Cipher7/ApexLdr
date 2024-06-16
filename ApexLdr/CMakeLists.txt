cmake_minimum_required(VERSION 3.26)
project(ApexLdr)

set(CMAKE_C_STANDARD   11)
set(CMAKE_C_COMPILER   x86_64-w64-mingw32-gcc)

include_directories(include)

set(APEXLDR_SRC
        src/main.c
)

add_executable(ApexLdr ${APEXLDR_SRC})
target_compile_options(ApexLdr PRIVATE -s -w -static -fpermissive -Wl,--subsystem,console -nostdlib -Wl,--entry="Main" -lkernel32 -luser32 -masm=intel)
