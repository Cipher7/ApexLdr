#pragma once

#include <windows.h>
#include <winhttp.h>

typedef HINTERNET(WINAPI* fnWinHttpOpen)(LPCWSTR pwszUserAgent, DWORD dwAccessType, LPCWSTR pwszProxyName, LPCWSTR pwszProxyBypass, DWORD dwFlags);

typedef ULONGLONG(WINAPI* fnGetTickCount64)();

typedef HINTERNET(WINAPI* fnWinHttpConnect)(HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved);

typedef HINTERNET(WINAPI* fnWinHttpOpenRequest)(HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR* ppwszAcceptTypes, DWORD dwFlags);

typedef BOOL(WINAPI* fnWinHttpSendRequest)(HINTERNET hRequest, LPCWSTR pwszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext);

typedef BOOL(WINAPI* fnWinHttpReceiveResponse)(HINTERNET hRequest, LPVOID lpReserved);

typedef BOOL(WINAPI* fnWinHttpReadData)(HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);

typedef BOOL(WINAPI* fnWinHttpCloseHandle)(HINTERNET hInternet);

typedef HMODULE(WINAPI* fnLoadLibraryA)(LPCSTR lpLibFileName);
