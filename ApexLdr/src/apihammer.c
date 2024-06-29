#include <windows.h>
#include <stdio.h>
#include <time.h>
#include "structs.h"

#define TMPFILE	L"delays.tmp"

BOOL ApiHammering(DWORD Stress)
{
	CHAR		szPath[MAX_PATH * 2];
	CHAR		szTmpPath[MAX_PATH];
	HANDLE		hRFile = INVALID_HANDLE_VALUE;
	HANDLE		hWFile = INVALID_HANDLE_VALUE;
	DWORD		dwNumberOfBytesRead = (DWORD) NULL;
	DWORD		dwNumberOfBytesWritten = (DWORD) NULL;
	PBYTE		pRandBuffer = NULL;
	SIZE_T		sBufferSize = 0xFFFFF;
	INT			Random = 0;

	// Fetch tmp folder
	if (!GetTempPathA(MAX_PATH, szTmpPath)) {
		goto _Cleanup;
	}

	apis.msvcrt.sprintf(szPath, L"%s%s", szTmpPath, TMPFILE);

	for (SIZE_T i = 0; i < Stress; i++)
	{
		if ((hWFile = CreateFileA(szPath, GENERIC_WRITE, (DWORD) NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL)) == INVALID_HANDLE_VALUE) {
			goto _Cleanup;
		}

		pRandBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBufferSize);
		apis.msvcrt.srand(apis.msvcrt._time64(NULL));
		Random = apis.msvcrt.rand() % 0xFF;
		apis.msvcrt.memset(pRandBuffer, Random, sBufferSize);

		if (!WriteFile(hWFile, pRandBuffer, sBufferSize, &dwNumberOfBytesWritten, NULL) || dwNumberOfBytesWritten != sBufferSize)
        {
			goto _Cleanup;
		}

		apis.msvcrt.memset(pRandBuffer,0, sBufferSize);
		CloseHandle(hWFile);

		if ((hRFile = CreateFileW(szPath, GENERIC_READ, (DWORD) NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL)) == INVALID_HANDLE_VALUE)
        {
			goto _Cleanup;
		}

		if (!ReadFile(hRFile, pRandBuffer, sBufferSize, &dwNumberOfBytesRead, NULL) || dwNumberOfBytesRead != sBufferSize)
        {
			goto _Cleanup;
		}

		apis.msvcrt.memset(pRandBuffer,0, sBufferSize);
		HeapFree(GetProcessHeap(), (DWORD) NULL, pRandBuffer);

		CloseHandle(hRFile);
	}
	return TRUE;

_Cleanup:
	return FALSE;
}