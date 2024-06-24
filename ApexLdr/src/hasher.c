#include "hasher.h"

#define     CRC_POLYNOMIAL      0xEDB88320

UINT32 CRC32B (LPCSTR cString)
{
    UINT32      uMask   = 0x00;
    UINT32      uHash   = 0xFFFFFFFF;
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