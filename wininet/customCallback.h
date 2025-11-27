/*
 * customCallback interface and dependencies.
 *
 * This header keeps the transport-specific callback self contained so
 * the hook template can include it without additional wiring.
 */

#pragma once

#include <windows.h>
#include <wininet.h>

// Minimal imports required by the default customCallback implementation.
#ifndef KERNEL32$GetProcessHeap
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
#endif
#ifndef KERNEL32$CreateFileA
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
#endif
#ifndef KERNEL32$WriteFile
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
#endif
#ifndef KERNEL32$CloseHandle
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$CloseHandle(HANDLE);
#endif
#ifndef KERNEL32$Sleep
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$Sleep(DWORD);
#endif
#ifndef KERNEL32$GetFileSize
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
#endif
#ifndef KERNEL32$HeapAlloc
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
#endif
#ifndef KERNEL32$HeapFree
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
#endif
#ifndef KERNEL32$ReadFile
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
#endif

#ifndef MSVCRT$printf
DECLSPEC_IMPORT int    MSVCRT$printf(const char *format, ...);
#endif
#ifndef MSVCRT$strlen
DECLSPEC_IMPORT size_t MSVCRT$strlen(const char *str);
#endif

/*
 * customCallback specification:
 *
 * This is what you modify. You can put any transport you want here, the file read/write is just my
 * PoC and tutorial code to show the spec.
 *
 * 1. encodedRequest is a base64-encoded JSON of the HTTP request (method/scheme/host/port/path/headers/body)
 *    - you dont need to touch this content - just send it to the broker.py script somehow and get the response.
 * 2. return the response as a char*
 *
 * You can return NULL to skip handling and let WinInet continue normally. (e.g. timeout)
 *
 * Profit!
 *
 * Hopefully this is easy enough to use xD
 */
static char *customCallback(const char *encodedRequest, const char *host, INTERNET_PORT port)
{
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    DWORD bytesWritten = 0;
    DWORD bytesRead = 0;
    MSVCRT$printf("[customCallback] received request for %s:%u\n", host ? host : "", (unsigned int)port);
    MSVCRT$printf("[customCallback] writing request to request.txt");

    HANDLE hReq = KERNEL32$CreateFileA("request.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hReq == INVALID_HANDLE_VALUE) {
        MSVCRT$printf("\n[customCallback] failed to open request.txt for write\n");
        return NULL;
    }

    DWORD reqLen = encodedRequest ? (DWORD)MSVCRT$strlen(encodedRequest) : 0;
    if (encodedRequest != NULL && reqLen > 0) {
        KERNEL32$WriteFile(hReq, encodedRequest, reqLen, &bytesWritten, NULL);
    }
    KERNEL32$CloseHandle(hReq);

    MSVCRT$printf("\n[customCallback] wrote %lu bytes, sleeping 500ms before reading response", (unsigned long)bytesWritten);
    KERNEL32$Sleep(500);

    HANDLE hResp = KERNEL32$CreateFileA("response.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hResp == INVALID_HANDLE_VALUE) {
        MSVCRT$printf("\n[customCallback] failed to open response.txt for read\n");
        return NULL;
    }

    DWORD fileSize = KERNEL32$GetFileSize(hResp, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        MSVCRT$printf("\n[customCallback] invalid file size for response.txt\n");
        KERNEL32$CloseHandle(hResp);
        return NULL;
    }

    if (fileSize == 0) {
        MSVCRT$printf("\n[customCallback] empty response.txt detected; returning no data to caller\n");
        KERNEL32$CloseHandle(hResp);
        return NULL;
    }

    char *responseBuf = (char *)KERNEL32$HeapAlloc(hHeap, 0, fileSize + 1);
    if (responseBuf == NULL) {
        MSVCRT$printf("\n[customCallback] allocation failed for response buffer\n");
        KERNEL32$CloseHandle(hResp);
        return NULL;
    }

    if (KERNEL32$ReadFile(hResp, responseBuf, fileSize, &bytesRead, NULL) == FALSE) {
        MSVCRT$printf("\n[customCallback] read failed from response.txt\n");
        KERNEL32$HeapFree(hHeap, 0, responseBuf);
        KERNEL32$CloseHandle(hResp);
        return NULL;
    }

    while (bytesRead > 0 && (responseBuf[bytesRead - 1] == '\n' || responseBuf[bytesRead - 1] == '\r')) {
        bytesRead--;
    }

    if (bytesRead == 0) {
        MSVCRT$printf("\n[customCallback] response.txt contained no data after trimming; returning no data to caller\n");
        KERNEL32$HeapFree(hHeap, 0, responseBuf);
        KERNEL32$CloseHandle(hResp);
        return NULL;
    }

    responseBuf[bytesRead] = '\0';
    KERNEL32$CloseHandle(hResp);

    MSVCRT$printf("\n[customCallback] read %lu bytes from response.txt\n", (unsigned long)bytesRead);
    return responseBuf;
}

