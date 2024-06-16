#ifndef APEXLDR_UNHOOK_H
#define APEXLDR_UNHOOK_H

#include <windows.h>
#include "structs.h"

#define CRC_POLYNOMIAL  0xEDB88320
#define text_CRC32  0xA21C1EA3
#define 	OBJ_CASE_INSENSITIVE   0x00000040

//global variables
extern SIZE_T   g_sTextSectionSize;
extern LPVOID   g_pLocalTxtSectionAddress;
extern LPVOID	g_pKnownDllTxtSectionAddress;

UINT32 CRC32B(LPCSTR cString);

#define CRCHASH(STR)    ( CRC32B( (LPCSTR)STR ) )

#endif //APEXLDR_UNHOOK_H
