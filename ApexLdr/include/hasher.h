#ifndef APEXLDR_HASHER_H
#define APEXLDR_HASHER_H

#include <windows.h>

UINT32 CRC32B(LPCSTR cString);

#define CRCHASH(STR)    ( CRC32B( (LPCSTR)STR ) )

#define WinHttpOpen_CRC32        0x2D697D39
#define WinHttpConnect_CRC32     0x6F50B6C6
#define WinHttpOpenRequest_CRC32         0xB8172A42
#define WinHttpSendRequest_CRC32         0xCEE9B4F7
#define WinHttpReceiveResponse_CRC32     0x46BB61F9
#define WinHttpReadData_CRC32    0x2E5251CA
#define WinHttpCloseHandle_CRC32         0x6A29F9F4
#define GetTickCount64_CRC32     0x517FEF08
#define memset_CRC32     0x8463960A
#define _time64_CRC32    0x63985F1E
#define printf_CRC32     0xD21739F1
#define rand_CRC32       0x18C6F574
#define sprintf_CRC32    0x23398D9A
#define srand_CRC32      0x41D2476A
#define memcpy_CRC32     0xD141AFD3
#define memcmp_CRC32     0x57F17B6B
#define strlen_CRC32     0x025D112D
#define realloc_CRC32    0x1C13E31D
#define malloc_CRC32     0xA719DEAF
#define wcscat_CRC32     0x61E2048F
#define wcslen_CRC32     0xF3B07FCC
#define LoadLibraryA_CRC32       0x3FC1BD8D
#define CreateThreadpoolTimer_CRC32      0xCC315CB0
#define SetThreadpoolTimer_CRC32         0x9B52D1CC
#define WaitForSingleObject_CRC32        0xE058BB45
#define AddVectoredExceptionHandler_CRC32        0x91765761
#define RemoveVectoredExceptionHandler_CRC32     0x8670F6CA

#define text_CRC32       0xA21C1EA3

#define kernel32_CRC32   0x6AE69F02

#define winhttp_CRC32    0xF5FAD117

#define ntdll_CRC32      0x84C05E40

#define msvcrt_CRC32     0x161B8E25
#endif //APEXLDR_HASHER_H
